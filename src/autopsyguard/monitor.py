"""Main monitoring loop that orchestrates all detectors.

The monitor operates in three states:
  WAITING  — Autopsy is not running or the case is not active; detectors are idle.
  ACTIVE   — Autopsy is running with an active case; detectors are polling.
  FINISHED — Autopsy shut down gracefully (lock file removed); monitoring stops.

This ensures we only monitor during actual ingest/processing, not on idle case dirs.
"""

from __future__ import annotations

import enum
import logging
import time
from collections import defaultdict

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.detectors.hang_detector import HangDetector
from autopsyguard.detectors.jvm_crash_detector import JvmCrashDetector
from autopsyguard.detectors.log_detector import LogDetector
from autopsyguard.detectors.process_detector import ProcessDetector
from autopsyguard.detectors.resource_detector import ResourceDetector
from autopsyguard.detectors.solr_detector import SolrDetector
from autopsyguard.utils.solr_health import SolrHealthCache
from autopsyguard.models import CrashEvent, Severity
from autopsyguard.notifiers import EmailNotifier, WhatsAppNotifier, TelegramNotifier
from autopsyguard.platform_utils import (
    get_case_lock_file,
    get_global_lock_file,
)
from autopsyguard.utils.process_utils import find_autopsy_pid
from autopsyguard.utils.metrics_store import MetricsStore

logger = logging.getLogger(__name__)


class MonitorState(enum.Enum):
    WAITING = "waiting"
    ACTIVE = "active"
    FINISHED = "finished"


class Monitor:
    """Runs all detectors in a polling loop and collects events.

    Only activates detectors when Autopsy is running AND the case is open
    (lock file present).  This prevents false positives on idle case dirs.
    """

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        # Record monitor start time for heuristics used by detectors
        monitor_start = time.time()

        # Shared Solr health cache to avoid duplicate probes per cycle
        solr_cache = SolrHealthCache(config)

        # Create LogDetector first so HangDetector can query ingest state
        self._log_detector = LogDetector(config)

        self.detectors: list[BaseDetector] = [
            ProcessDetector(config),
            JvmCrashDetector(config),
            self._log_detector,
            HangDetector(config, solr_cache=solr_cache, log_detector=self._log_detector),
            ResourceDetector(config),
            SolrDetector(config, solr_cache=solr_cache, monitor_start=monitor_start),
        ]
        self.notifier = EmailNotifier(config)
        self.whatsapp = WhatsAppNotifier(config)
        self.telegram = TelegramNotifier(config)
        self._metrics_store = MetricsStore(case_dir=config.case_dir)
        self._running = False
        self._state = MonitorState.WAITING
        self._last_report_time = time.time()
        self._events_since_last_report = 0
        self._report_count = 0
        # Per-detector failure tracking and temporary disable windows
        self._detector_fail_counts: dict[str, int] = defaultdict(int)
        self._detector_disabled_until: dict[str, float] = {}
        
        # Track previous ingest state to detect transitions
        self._was_ingest_running = False
        self._ingest_start_time: float | None = None
        self._has_ingest_started_ever = False

    def _is_autopsy_running(self) -> bool:
        """Check if the Autopsy process is running.
        
        We start monitoring as soon as the process exists so we can detect
        crashes even before a case is fully opened.
        """
        pid = find_autopsy_pid()
        return pid is not None

    def run_once(self) -> list[CrashEvent]:
        """Execute a single detection cycle across all detectors."""
        events: list[CrashEvent] = []
        now = time.time()
        for detector in self.detectors:
            disabled_until = self._detector_disabled_until.get(detector.name, 0)
            if now < disabled_until:
                logger.debug(
                    "Skipping disabled detector %s until %s",
                    detector.name,
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(disabled_until)),
                )
                continue
            try:
                new_events = detector.check()
                events.extend(new_events)
                # Reset failure count on success
                self._detector_fail_counts[detector.name] = 0
            except Exception as e:
                # Increment failure count and apply exponential backoff
                count = self._detector_fail_counts.get(detector.name, 0) + 1
                self._detector_fail_counts[detector.name] = count
                backoff = min(300, 10 * (2 ** count))
                self._detector_disabled_until[detector.name] = time.time() + backoff
                logger.warning(
                    "Detector %s failed (%d times), disabling for %ds: %s",
                    detector.name,
                    count,
                    backoff,
                    e,
                )

        return events

    def run(self) -> None:
        """Start the continuous monitoring loop.

        Waits for Autopsy + active case before running detectors.
        Distinguishes graceful shutdown from crashes.
        """
        self._running = True
        self._state = MonitorState.WAITING
        logger.info("Waiting for Autopsy process...")

        try:
            while self._running:
                if self._state == MonitorState.WAITING:
                    self._handle_waiting()
                elif self._state == MonitorState.ACTIVE:
                    self._handle_active()
                elif self._state == MonitorState.FINISHED:
                    break

                time.sleep(self.config.poll_interval)

        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            self._metrics_store.close()
            logger.info("Monitor stopped")

    def stop(self) -> None:
        """Signal the monitoring loop to stop."""
        self._running = False

    def _handle_waiting(self) -> None:
        """Wait until Autopsy is running."""
        if self._is_autopsy_running():
            self._state = MonitorState.ACTIVE
            logger.info("✅ Autopsy detected — monitoring active")
        else:
            logger.debug("Waiting for Autopsy process...")

    def _handle_active(self) -> None:
        """Run detectors while the case is being processed."""
        self._metrics_store.record_sample()
        events = self.run_once()
        
        if events:
            # Send immediate alert for critical/warning events
            alert_events = [e for e in events if e.severity in (Severity.CRITICAL, Severity.WARNING)]
            if alert_events and self._has_ingest_started_ever:
                self.notifier.send_alert(alert_events)
                self.whatsapp.send_alert(alert_events)
                self.telegram.send_alert(alert_events)
            elif alert_events:
                logger.info("Alerts generated but muted because ingest has not started yet.")
                
            for event in events:
                self._handle_event(event)
                self._events_since_last_report += 1

        # Check for ingest state transitions
        is_ingest_running = self._log_detector.ingest_running
        if is_ingest_running and not self._was_ingest_running:
            # Ingest just started
            self._ingest_start_time = self._log_detector.ingest_start_time
            self._was_ingest_running = True
            self._has_ingest_started_ever = True
            
        elif not is_ingest_running and self._was_ingest_running:
            # Ingest just finished
            duration = 0.0
            if self._ingest_start_time is not None:
                duration = time.time() - self._ingest_start_time
            
            logger.info("Ingest job finished after %.1fs. Sending reports.", duration)
            self.notifier.send_ingest_report(duration)
            self.whatsapp.send_ingest_report(duration)
            self.telegram.send_ingest_report(duration)
            
            self._was_ingest_running = False
            self._ingest_start_time = None

        # Check periodic reporting (Heartbeat)
        now = time.time()
        elapsed_hours = (now - self._last_report_time) / 3600.0
        if elapsed_hours >= self.config.report_interval_hours:
            if self._has_ingest_started_ever:
                # Fetch a small buffer before the last report time to ensure
                # we have enough samples for chart rendering even on the
                # first/short-interval reports.
                buffer_seconds = max(60, int(self.config.poll_interval * 3))
                since_ts = max(0.0, self._last_report_time - buffer_seconds)
                metrics_samples = self._metrics_store.fetch_samples(since_ts=since_ts)
                self.notifier.send_report(
                    system_status="O sistema AutopsyGuard está ATIVO e a processar dados normalmente.",
                    events_last_period=self._events_since_last_report,
                    metrics_samples=metrics_samples,
                )
                self.whatsapp.send_report(
                    system_status="O sistema AutopsyGuard está ATIVO e a processar dados normalmente.",
                    events_last_period=self._events_since_last_report,
                    metrics_samples=metrics_samples,
                )
                self.telegram.send_report(
                    system_status="O sistema AutopsyGuard está ATIVO e a processar dados normalmente.",
                    events_last_period=self._events_since_last_report,
                    metrics_samples=metrics_samples,
                )
            else:
                logger.info("Heartbeat skipped because ingest has not started yet.")
                
            self._last_report_time = now
            self._events_since_last_report = 0
            self._report_count += 1

        # Check if Autopsy shut down gracefully (process gone + lock removed)
        pid = find_autopsy_pid()
        lock_exists = (
            get_case_lock_file(self.config.case_dir).exists()
            or get_global_lock_file().exists()
        )

        if pid is None and not lock_exists:
            # Graceful shutdown: process exited and lock file was cleaned up
            self._state = MonitorState.FINISHED
            logger.info("Autopsy finished — case complete")
        elif pid is None and lock_exists:
            # Process gone but lock file remains — crash already detected
            # by ProcessDetector; stay active in case Autopsy restarts
            pass

    @staticmethod
    def _handle_event(event: CrashEvent) -> None:
        """Log a detected event."""
        severity_icon = "🔴" if event.severity.name == "CRITICAL" else "🟡"
        logger.warning(
            "%s %s: %s", 
            severity_icon, 
            event.crash_type.name, 
            event.message
        )
