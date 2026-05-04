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
from autopsyguard.notifier import EmailNotifier
from autopsyguard.whatsapp_notifier import WhatsAppNotifier
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
        log_detector = LogDetector(config)

        self.detectors: list[BaseDetector] = [
            ProcessDetector(config),
            JvmCrashDetector(config),
            log_detector,
            HangDetector(config, solr_cache=solr_cache, log_detector=log_detector),
            ResourceDetector(config),
            SolrDetector(config, solr_cache=solr_cache, monitor_start=monitor_start),
        ]
        self.notifier = EmailNotifier(config)
        self.whatsapp = WhatsAppNotifier(config)
        self._metrics_store = MetricsStore(case_dir=config.case_dir)
        self._running = False
        self._state = MonitorState.WAITING
        self._last_report_time = time.time()
        self._events_since_last_report = 0
        self._report_count = 0
        # Per-detector failure tracking and temporary disable windows
        self._detector_fail_counts: dict[str, int] = defaultdict(int)
        self._detector_disabled_until: dict[str, float] = {}

    def _is_case_active(self) -> bool:
                """Check if Autopsy is running and the case is open.

                Rationale:
                - Autopsy creates a per-case lock file inside the case `Log/` directory
                    when a case is opened.  However, on startup NetBeans/Autopsy also
                    creates a global `messages.log.lck` under the user var/log tree
                    shortly after the JVM starts.  We treat either lock as evidence the
                    application is active because the global lock is a reliable early
                    indicator that Autopsy has started its runtime and may soon open a
                    case.

                Notes on behaviour:
                - This can cause the monitor to enter `ACTIVE` briefly while the
                    Autopsy UI is still showing the "Open Case" dialog (global lock is
                    created ~2–3s after process start).  This is intentional and benign:
                    detectors initialize by seeking to EOF on first run so they won't
                    reprocess historical log data, and active monitoring will correctly
                    pick up once a case is actually opened.
                - The global lock is used as a pragmatic early proxy to avoid missing
                    short-lived case activity; it reduces race conditions when the
                    monitor starts before Autopsy has finished initialization.
                """
                pid = find_autopsy_pid()
                # Consider either a case-level lock or the global NetBeans messages lock
                lock_exists = (
                        get_case_lock_file(self.config.case_dir).exists()
                        or get_global_lock_file().exists()
                )
                return pid is not None and lock_exists

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
        """Wait until Autopsy is running and the case is active."""
        if self._is_case_active():
            self._state = MonitorState.ACTIVE
            logger.info("✅ Autopsy detected — monitoring active")
        else:
            pid = find_autopsy_pid()
            lock = (
                get_case_lock_file(self.config.case_dir).exists()
                or get_global_lock_file().exists()
            )
            logger.debug(
                "Waiting... (process: %s, lock: %s)",
                pid if pid else "no",
                "yes" if lock else "no",
            )

    def _handle_active(self) -> None:
        """Run detectors while the case is being processed."""
        self._metrics_store.record_sample()
        events = self.run_once()
        
        if events:
            # Send immediate alert for critical/warning events
            alert_events = [e for e in events if e.severity in (Severity.CRITICAL, Severity.WARNING)]
            if alert_events:
                self.notifier.send_alert(alert_events)
                self.whatsapp.send_alert(alert_events)
                
            for event in events:
                self._handle_event(event)
                self._events_since_last_report += 1

        # Check periodic reporting (Heartbeat)
        now = time.time()
        elapsed_hours = (now - self._last_report_time) / 3600.0
        if elapsed_hours >= self.config.report_interval_hours:
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
