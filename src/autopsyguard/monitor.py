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
from autopsyguard.utils.case_telemetry import collect_case_telemetry
from autopsyguard.utils.i18n import tr
from autopsyguard.models import CrashEvent, CrashType, Severity
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
        self._solr_cache = solr_cache

        # Create LogDetector first so HangDetector can query ingest state
        self._log_detector = LogDetector(config, monitor_start=monitor_start)

        self._solr_detector = SolrDetector(config, solr_cache=solr_cache, monitor_start=monitor_start)
        self.detectors: list[BaseDetector] = [
            ProcessDetector(config),
            JvmCrashDetector(config),
            self._log_detector,
            HangDetector(config, solr_cache=solr_cache, log_detector=self._log_detector),
            ResourceDetector(config),
            self._solr_detector,
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
        # Correlate bursts of detector alerts into a single incident to reduce
        # multi-detector alert noise (e.g., OOM -> HANG -> SOLR down chains).
        self._correlation_window_seconds = max(15.0, self.config.poll_interval * 2.0)
        self._pending_alert_events: list[CrashEvent] = []
        self._pending_alert_keys: set[str] = set()
        self._pending_alert_started_at: float | None = None
        # Crash types that should bypass the correlation delay and alert
        # immediately after detection.
        self._priority_alert_types: set[CrashType] = {
            CrashType.PROCESS_DISAPPEARED,
            CrashType.ABNORMAL_EXIT,
            CrashType.JVM_CRASH,
            CrashType.SOLR_CRASH,
            CrashType.ZOMBIE,
        }

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
            
            # Send an immediate startup confirmation to the user
            self.notifier.send_startup_message()
            self.whatsapp.send_startup_message()
            self.telegram.send_startup_message()
        else:
            logger.debug("Waiting for Autopsy process...")

    def _handle_active(self) -> None:
        """Run detectors while the case is being processed."""
        self._metrics_store.record_sample()
        events = self.run_once()
        now = time.time()

        # Send immediate alerts for critical/warning events, but correlate
        # multi-detector bursts into one incident before dispatching.
        alert_events = [e for e in events if e.severity in (Severity.CRITICAL, Severity.WARNING)]
        ready_alerts = self._collect_alert_notifications(alert_events, now)
        if ready_alerts and self._has_ingest_started_ever:
            self.notifier.send_alert(ready_alerts)
            self.whatsapp.send_alert(ready_alerts)
            self.telegram.send_alert(ready_alerts)
        elif ready_alerts:
            logger.info("Alerts generated but muted because ingest has not started yet.")

        if events:
            for event in events:
                self._handle_event(event)
                self._events_since_last_report += 1

        # Check for ingest state transitions
        is_ingest_running = self._log_detector.ingest_running
        if is_ingest_running and not self._was_ingest_running:
            # Ingest just started
            self._ingest_start_time = self._log_detector.ingest_start_time
            self._was_ingest_running = True
            
            if not self._has_ingest_started_ever:
                # Align the report timer exactly to the start of the ingest
                self._last_report_time = time.time()
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
        if self._has_ingest_started_ever:
            elapsed_hours = (now - self._last_report_time) / 3600.0
            if elapsed_hours >= self.config.report_interval_hours:
                # Fetch a small buffer before the last report time to ensure
                # we have enough samples for chart rendering even on the
                # first/short-interval reports.
                buffer_seconds = max(60, int(self.config.poll_interval * 3))
                since_ts = max(0.0, self._last_report_time - buffer_seconds)
                metrics_samples = self._metrics_store.fetch_samples(since_ts=since_ts)
                now_ts = time.time()
                cpu_timeline = self._metrics_store.nearest_autopsy_cpu_samples(
                    now_ts=now_ts,
                    offsets_seconds=[0.0, 300.0, 900.0],
                )
                solr_status = None
                try:
                    solr_status = self._solr_cache.get_status()
                except Exception:
                    solr_status = None
                solr_metrics = None
                try:
                    solr_metrics = self._solr_detector.get_current_metrics()
                except Exception:
                    solr_metrics = None
                telemetry = collect_case_telemetry(
                    config=self.config,
                    solr_status=solr_status,
                    solr_metrics=solr_metrics,
                    cpu_snapshots=cpu_timeline,
                )
                status_mode = self._classify_runtime_status(telemetry=telemetry)
                status_text = self._status_text_for_mode(status_mode)
                
                self.notifier.send_report(
                    system_status=status_text,
                    events_last_period=self._events_since_last_report,
                    metrics_samples=metrics_samples,
                    telemetry=telemetry,
                )
                self.whatsapp.send_report(
                    system_status=status_text,
                    events_last_period=self._events_since_last_report,
                    metrics_samples=metrics_samples,
                    telemetry=telemetry,
                )
                self.telegram.send_report(
                    system_status=status_text,
                    events_last_period=self._events_since_last_report,
                    metrics_samples=metrics_samples,
                    telemetry=telemetry,
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
            # Flush any buffered correlation incident before shutdown.
            final_alerts = self._flush_pending_alerts(time.time(), force=True)
            if final_alerts and self._has_ingest_started_ever:
                self.notifier.send_alert(final_alerts)
                self.whatsapp.send_alert(final_alerts)
                self.telegram.send_alert(final_alerts)
            # Graceful shutdown: process exited and lock file was cleaned up
            self._state = MonitorState.FINISHED
            logger.info("Autopsy finished — case complete")
        elif pid is None and lock_exists:
            # Process gone but lock file remains — crash already detected
            # by ProcessDetector; stay active in case Autopsy restarts
            pass

    @staticmethod
    def _alert_event_key(event: CrashEvent) -> str:
        """Return a stable key for deduplicating buffered alert events."""
        return (
            f"{event.crash_type.value}|{event.severity.value}|{event.message}"
        )

    def _buffer_alert_events(self, events: list[CrashEvent], now: float) -> None:
        """Add alert events to the correlation buffer (deduplicated)."""
        if not events:
            return
        if self._pending_alert_started_at is None:
            self._pending_alert_started_at = now
        for event in events:
            key = self._alert_event_key(event)
            if key in self._pending_alert_keys:
                continue
            self._pending_alert_keys.add(key)
            self._pending_alert_events.append(event)

    def _build_correlated_incident(self, events: list[CrashEvent]) -> CrashEvent:
        """Build a single incident event from multiple correlated alerts."""
        critical_count = sum(1 for e in events if e.severity == Severity.CRITICAL)
        warning_count = sum(1 for e in events if e.severity == Severity.WARNING)
        event_types = sorted({e.crash_type.name for e in events})
        summary = " -> ".join(event_types)
        severity = Severity.CRITICAL if critical_count > 0 else Severity.WARNING
        return CrashEvent(
            crash_type=CrashType.CORRELATED_INCIDENT,
            severity=severity,
            message=f"Incidente correlacionado detectado: {summary}",
            details={
                "event_count": len(events),
                "critical_count": critical_count,
                "warning_count": warning_count,
                "event_types": event_types,
                "correlation_window_seconds": self._correlation_window_seconds,
                "events": [
                    {
                        "crash_type": e.crash_type.name,
                        "severity": e.severity.name,
                        "message": e.message[:180],
                    }
                    for e in events
                ],
            },
        )

    def _materialize_alert_batch(self, events: list[CrashEvent]) -> list[CrashEvent]:
        """Convert buffered events into dispatchable alert payload."""
        if not events:
            return []
        distinct_types = {e.crash_type for e in events}
        if len(distinct_types) >= 2:
            return [self._build_correlated_incident(events)]
        return list(events)

    def _flush_pending_alerts(self, now: float, *, force: bool = False) -> list[CrashEvent]:
        """Flush buffered alerts when correlation window expires or forced."""
        if not self._pending_alert_events:
            return []
        if not force and self._pending_alert_started_at is not None:
            age = now - self._pending_alert_started_at
            if age < self._correlation_window_seconds:
                return []

        ready = self._materialize_alert_batch(self._pending_alert_events)
        self._pending_alert_events = []
        self._pending_alert_keys.clear()
        self._pending_alert_started_at = None
        return ready

    def _collect_alert_notifications(self, alert_events: list[CrashEvent], now: float) -> list[CrashEvent]:
        """Collect and flush correlated alert notifications for this cycle."""
        pending_before = len(self._pending_alert_events)
        self._buffer_alert_events(alert_events, now)
        has_priority = any((e.crash_type in self._priority_alert_types) for e in alert_events)
        has_critical = any(e.severity == Severity.CRITICAL for e in alert_events)
        # Flush immediately when a critical/priority signal arrives and no
        # prior buffered incident exists. If there are already pending signals,
        # flush now to emit one grouped correlated incident.
        if (has_priority or has_critical) and (
            pending_before == 0 or len(self._pending_alert_events) > len(alert_events)
        ):
            return self._flush_pending_alerts(now, force=True)
        return self._flush_pending_alerts(now, force=False)

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

    def _classify_runtime_status(self, telemetry: dict[str, object]) -> str:
        """Classify runtime state for periodic human-facing reports."""
        if self._log_detector.ingest_running:
            return "PROCESSING"

        cpu_now = None
        try:
            cpu_now = (telemetry.get("autopsy_cpu_timeline") or {}).get("current")
        except Exception:
            cpu_now = None
        module_activity = telemetry.get("module_activity") or []
        solr = telemetry.get("solr") or {}
        solr_up = str(solr.get("state", "")).lower() == "up"
        solr_rt = solr.get("response_time_seconds")

        if module_activity:
            return "ACTIVE_NON_INGEST"
        if cpu_now is not None:
            try:
                if float(cpu_now) >= max(5.0, self.config.hang_cpu_threshold):
                    return "ACTIVE_NON_INGEST"
            except Exception:
                pass
        if solr_up and solr_rt is not None:
            try:
                if float(solr_rt) > 0.0:
                    return "ACTIVE_NON_INGEST"
            except Exception:
                pass
        return "IDLE"

    def _status_text_for_mode(self, mode: str) -> str:
        if mode == "PROCESSING":
            return tr(self.config, "status_processing")
        if mode == "ACTIVE_NON_INGEST":
            return tr(self.config, "status_active_non_ingest")
        return tr(self.config, "status_idle")
