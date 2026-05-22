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
from datetime import datetime
import re

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
from autopsyguard.utils.messages import tr
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.notifiers import EmailNotifier, WhatsAppNotifier, TelegramNotifier
from autopsyguard.platform_utils import (
    get_case_lock_file,
    get_global_lock_file,
)
from autopsyguard.utils.process_utils import find_autopsy_pid
from autopsyguard.utils.metrics_store import MetricsStore

logger = logging.getLogger(__name__)

_NONFATAL_SOLR_PING_LOG_PATTERN = re.compile(
    r"Unknown RequestHandler \(qt\):\s*/?search",
    re.IGNORECASE,
)
_NON_ACTIONABLE_VENDOR_NULL_PATTERN = re.compile(
    r"vendorname\s*==\s*null",
    re.IGNORECASE,
)
_INGEST_JOB_ID_PATTERN = re.compile(r"(?:ingest\s+)?job\s+id\s*=\s*(\d+)", re.IGNORECASE)
_DATA_SOURCE_PATTERN = re.compile(r"data source\s*=\s*([^,\)]+)", re.IGNORECASE)
_OBJECT_ID_PATTERN = re.compile(r"object id\s*=\s*(\d+)", re.IGNORECASE)
_UNKNOWN_CONTEXT_TOKENS = {"", "n/a", "na", "unknown", "none"}


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
        self._alert_cooldown_seconds = max(90.0, self.config.poll_interval * 12.0)
        self._last_alert_signature_at: dict[str, float] = {}
        self._shutdown_noise_grace_seconds = min(90.0, max(45.0, self.config.poll_interval * 12.0))
        self._shutdown_noise_grace_until: float = 0.0
        self._post_ingest_resource_grace_seconds = 90.0
        self._post_ingest_resource_grace_until: float = 0.0
        self._keyword_incident_ttl_seconds = 1800.0
        self._keyword_incidents: dict[str, dict[str, object]] = {}
        self._log_error_incident_ttl_seconds = 1800.0
        self._log_error_incidents: dict[str, dict[str, object]] = {}
        self._module_error_summary_since_report: dict[str, dict[str, object]] = {}
        self._period_events: list[CrashEvent] = []
        self._warning_reminder_seconds = 3 * 3600.0
        self._critical_reminder_seconds = 3600.0
        self._incident_resolve_quiet_seconds = max(300.0, self.config.poll_interval * 6.0)
        self._incident_state: dict[str, dict[str, object]] = {}
        self._console_repeat_window_seconds = max(60.0, self.config.poll_interval * 12.0)
        self._console_summary_idle_seconds = max(30.0, self.config.poll_interval * 6.0)
        self._console_log_suppression: dict[str, dict[str, float | str | int]] = {}
        self._context_fallback_state: dict[str, str | float] = {
            "ingest_job_id": "unknown",
            "data_source": "unknown",
            "last_seen": 0.0,
        }
        self._module_context_anchors: dict[str, dict[str, str | float]] = {}
        self._module_context_anchor_ttl_seconds = 300.0
        self._solr_outage_incident: dict[str, object] | None = None
        self._solr_outage_resolve_quiet_seconds = 120.0
        self._incident_sequence = 0
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
        pid = find_autopsy_pid()
        lock_exists = (
            get_case_lock_file(self.config.case_dir).exists()
            or get_global_lock_file().exists()
        )

        # During launcher/case-open warmup (before first ingest start), Autopsy
        # can transiently churn Solr child JVMs and replay Solr log warnings.
        # Suppress these warning-only signals to avoid misleading noise.
        if not self._has_ingest_started_ever and events:
            warmup_filtered: list[CrashEvent] = []
            for event in events:
                if event.crash_type in {CrashType.SOLR_CRASH, CrashType.LOG_ERROR}:
                    logger.debug(
                        "Suppressing pre-ingest warmup event: %s - %s",
                        event.crash_type.name,
                        event.message,
                    )
                    continue
                warmup_filtered.append(event)
            events = warmup_filtered

        # Check for ingest state transitions before alert dispatch so shutdown
        # grace suppression can apply to late Solr/log noise in the same cycle.
        is_ingest_running = self._log_detector.ingest_running
        if is_ingest_running and not self._was_ingest_running:
            # Ingest just started
            self._ingest_start_time = self._log_detector.ingest_start_time
            self._was_ingest_running = True
            self._keyword_incidents.clear()
            self._log_error_incidents.clear()
            self._module_error_summary_since_report.clear()
            self._period_events.clear()

            if not self._has_ingest_started_ever:
                # Align the report timer exactly to the start of the ingest
                self._last_report_time = time.time()
                self._events_since_last_report = 0
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
            self._shutdown_noise_grace_until = time.time() + self._shutdown_noise_grace_seconds
            self._post_ingest_resource_grace_until = time.time() + self._post_ingest_resource_grace_seconds

            self._was_ingest_running = False
            self._ingest_start_time = None

        # Send immediate alerts for critical/warning events, but correlate
        # multi-detector bursts into one incident before dispatching.
        alert_events = [e for e in events if e.severity in (Severity.CRITICAL, Severity.WARNING)]
        alert_events = self._filter_shutdown_noise_alerts(
            alert_events,
            now=now,
            pid=pid,
            lock_exists=lock_exists,
        )
        alert_events = self._filter_post_ingest_resource_alerts(alert_events, now=now)
        alert_events = self._aggregate_log_error_alerts(alert_events, now=now)
        alert_events = self._aggregate_keyword_search_alerts(alert_events, now=now)
        ready_alerts = self._collect_alert_notifications(alert_events, now)
        ready_alerts = self._filter_post_ingest_resource_alerts(ready_alerts, now=now)
        ready_alerts = self._filter_nonfatal_solr_ping_alerts(ready_alerts)
        ready_alerts = self._apply_solr_outage_policy(ready_alerts, now=now)
        recovery_alert = self._maybe_build_solr_outage_recovery_alert(now=now)
        if recovery_alert is not None:
            ready_alerts.append(recovery_alert)
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
                self._period_events.append(event)

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
                try:
                    nonfatal_warning = self._solr_detector.get_nonfatal_warning()
                    if (
                        solr_status is not None
                        and getattr(solr_status, "is_up", False)
                        and nonfatal_warning
                        and not getattr(solr_status, "error", None)
                    ):
                        solr_status.error = nonfatal_warning
                except Exception:
                    pass
                telemetry = collect_case_telemetry(
                    config=self.config,
                    solr_status=solr_status,
                    solr_metrics=solr_metrics,
                    cpu_snapshots=cpu_timeline,
                )
                telemetry["solr_outage_incident"] = self._solr_outage_telemetry_snapshot(now=now)
                telemetry["module_period_counters"] = self._build_module_period_counters(self._period_events)
                self._inject_module_error_summary(telemetry)
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
                self._module_error_summary_since_report.clear()
                self._period_events.clear()

        self._flush_console_event_summaries(now=now)

        # Check if Autopsy shut down gracefully (process gone + lock removed)
        if pid is None and not lock_exists:
            self._flush_console_event_summaries(now=time.time(), force=True)
            # Flush any buffered correlation incident before shutdown.
            final_alerts = self._flush_pending_alerts(time.time(), force=True)
            final_alerts = self._filter_shutdown_noise_alerts(
                final_alerts,
                now=time.time(),
                pid=pid,
                lock_exists=lock_exists,
            )
            final_alerts = self._filter_post_ingest_resource_alerts(final_alerts, now=time.time())
            final_alerts = self._aggregate_keyword_search_alerts(final_alerts, now=time.time())
            final_alerts = self._filter_nonfatal_solr_ping_alerts(final_alerts)
            if final_alerts and self._has_ingest_started_ever:
                self.notifier.send_alert(final_alerts)
                self.whatsapp.send_alert(final_alerts)
                self.telegram.send_alert(final_alerts)
            # Graceful shutdown: process exited and lock file was cleaned up
            self._state = MonitorState.FINISHED
            logger.info("Autopsy finished — case complete")

            # Collect session stats and notify all channels
            self._send_shutdown_notifications()
        elif pid is None and lock_exists:
            # Process gone but lock file remains — crash already detected
            # by ProcessDetector; stay active in case Autopsy restarts
            pass

    def _send_shutdown_notifications(self) -> None:
        """Collect session stats and send shutdown summary to all channels."""
        import os
        from pathlib import Path

        uptime = self.notifier.get_uptime()

        # Count events by severity across the entire session
        all_events = self._period_events
        total = len(all_events)
        critical = sum(1 for e in all_events if e.severity == Severity.CRITICAL)
        warnings = sum(1 for e in all_events if e.severity == Severity.WARNING)

        # Case folder size
        case_dir = self.config.case_dir
        try:
            case_size_bytes = sum(
                f.stat().st_size
                for f in Path(case_dir).rglob("*")
                if f.is_file()
            )
            case_size = self._bytes_to_human(case_size_bytes)
        except OSError:
            case_size = "N/A"

        # autopsy.db size
        db_path = case_dir / "autopsy.db"
        try:
            db_size = self._bytes_to_human(db_path.stat().st_size) if db_path.exists() else "N/A"
        except OSError:
            db_size = "N/A"

        stats = {
            "uptime": uptime,
            "total_events": total,
            "critical_count": critical,
            "warning_count": warnings,
            "reports_sent": self._report_count,
            "case_size": case_size,
            "db_size": db_size,
        }

        self.notifier.send_shutdown_message(stats)
        self.whatsapp.send_shutdown_message(stats)
        self.telegram.send_shutdown_message(stats)

    @staticmethod
    def _bytes_to_human(v: int | float) -> str:
        """Convert bytes to a human-readable string."""
        value = float(v)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024 or unit == "TB":
                return f"{value:.1f}{unit}"
            value /= 1024.0
        return f"{value:.1f}TB"

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
        
        # Extract the first available log file to ensure the email notifier can attach it
        file_path = next((e.details.get("file") for e in events if e.details and e.details.get("file")), None)

        return CrashEvent(
            crash_type=CrashType.CORRELATED_INCIDENT,
            severity=severity,
            message=f"Correlated incident detected: {summary}",
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
                "file": file_path,
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
            ready = self._flush_pending_alerts(now, force=True)
            return self._apply_alert_cooldown(ready, now)
        ready = self._flush_pending_alerts(now, force=False)
        return self._apply_alert_cooldown(ready, now)

    @staticmethod
    def _extract_signature_module(text: str) -> str:
        low = text.lower()
        if "keyword search" in low or "keywordsearch" in low:
            return "Keyword Search"
        if "solr" in low:
            return "Solr"
        if "recent activity" in low or "recentactivity" in low:
            return "Recent Activity"
        if "photorec" in low:
            return "PhotoRec Carver"
        if "embedded file extractor" in low:
            return "Embedded File Extractor"
        if "tika" in low:
            return "Tika"
        return "General"

    @staticmethod
    def _extract_signature_family(text: str) -> str:
        low = text.lower()
        checks = (
            ("stackoverflowerror", "stack_overflow"),
            ("codermalfunctionerror", "coder_malfunction"),
            ("arrayindexoutofboundsexception", "array_index_oob"),
            ("saxparseexception", "sax_parse"),
            ("tikaexception", "tika_exception"),
            ("sevenzipexception", "seven_zip"),
            ("truncated zip file", "truncated_zip"),
            ("eofexception", "eof"),
            ("filenotfoundexception", "file_not_found"),
            ("illegalargumentexception", "illegal_argument"),
            ("zipexception", "zip_exception"),
        )
        for token, label in checks:
            if token in low:
                return label
        return "generic_log_error"

    @staticmethod
    def _normalize_context_value(value: object) -> str | None:
        raw = str(value or "").strip()
        if raw.lower() in _UNKNOWN_CONTEXT_TOKENS:
            return None
        return raw

    @staticmethod
    def _context_scope_key(ingest_job_id: str, data_source: str) -> str:
        return f"job={ingest_job_id.lower()}|src={data_source.lower()}"

    def _active_ingest_context(self) -> tuple[str | None, str | None]:
        job_id = self._normalize_context_value(getattr(self._log_detector, "active_ingest_job_id", None))
        data_source = self._normalize_context_value(getattr(self._log_detector, "active_data_source", None))
        return job_id, data_source

    def _remember_context(self, ingest_job_id: str, data_source: str, *, now: float) -> None:
        if self._normalize_context_value(ingest_job_id) is not None:
            self._context_fallback_state["ingest_job_id"] = ingest_job_id
        if self._normalize_context_value(data_source) is not None:
            self._context_fallback_state["data_source"] = data_source
        self._context_fallback_state["last_seen"] = now

    def _resolve_context(
        self,
        *,
        line_text: str,
        details: dict[str, object],
        now: float,
    ) -> tuple[str, str]:
        # precedence: explicit line context > event details > active ingest context > last-open incident context
        line_job = self._normalize_context_value(self._extract_first_match(_INGEST_JOB_ID_PATTERN, line_text))
        line_source = self._normalize_context_value(self._extract_first_match(_DATA_SOURCE_PATTERN, line_text))
        detail_job = self._normalize_context_value(details.get("ingest_job_id"))
        detail_source = self._normalize_context_value(details.get("data_source"))
        active_job, active_source = self._active_ingest_context()
        fallback_job = self._normalize_context_value(self._context_fallback_state.get("ingest_job_id"))
        fallback_source = self._normalize_context_value(self._context_fallback_state.get("data_source"))

        ingest_job_id = line_job or detail_job or active_job or fallback_job or "unknown"
        data_source = line_source or detail_source or active_source or fallback_source or "unknown"
        if ingest_job_id != "unknown" or data_source != "unknown":
            self._remember_context(ingest_job_id, data_source, now=now)
        return ingest_job_id, data_source

    def _anchor_module_for_context(
        self,
        *,
        ingest_job_id: str,
        data_source: str,
        module: str,
        now: float,
    ) -> None:
        if not module or module.lower() == "general":
            return
        key = self._context_scope_key(ingest_job_id, data_source)
        self._module_context_anchors[key] = {"module": module, "last_seen": now}

    def _module_from_recent_anchor(
        self,
        *,
        ingest_job_id: str,
        data_source: str,
        now: float,
    ) -> str | None:
        key = self._context_scope_key(ingest_job_id, data_source)
        anchor = self._module_context_anchors.get(key)
        if not anchor:
            return None
        if (now - float(anchor.get("last_seen", 0.0))) > self._module_context_anchor_ttl_seconds:
            return None
        module = str(anchor.get("module") or "").strip()
        return module or None

    @staticmethod
    def _module_from_signature_family(signature: str, text: str) -> str | None:
        low = text.lower()
        if signature in {"tika_exception", "sax_parse"}:
            return "Tika"
        if (
            "unable to send document batch to solr" in low
            or "server refused connection" in low
            or "http host connect exception" in low
            or "connectexception: connection refused" in low
        ):
            return "Solr"
        if "keywordsearchmoduleexception" in low or "could not add batched documents to index" in low:
            return "Keyword Search"
        return None

    def _event_incident_signature(self, event: CrashEvent) -> str:
        details = event.details or {}
        log_line = str(details.get("line") or details.get("log_line") or "")
        payload = f"{event.message} {log_line}".strip()
        if event.crash_type == CrashType.HIGH_RESOURCE_USAGE:
            low = payload.lower()
            subtype = "cpu"
            if "memory" in low:
                subtype = "memory"
            elif "disk" in low:
                subtype = "disk"
            return f"HIGH_RESOURCE_USAGE|{subtype}"
        if event.crash_type == CrashType.LOG_ERROR:
            module = str(details.get("module") or self._extract_signature_module(payload))
            family = self._extract_signature_family(payload)
            job_id = (
                str(details.get("ingest_job_id") or "").strip()
                or self._extract_first_match(_INGEST_JOB_ID_PATTERN, payload)
                or "N/A"
            )
            data_source = (
                str(details.get("data_source") or "").strip()
                or self._extract_first_match(_DATA_SOURCE_PATTERN, payload)
                or "N/A"
            )
            return f"LOG_ERROR|{module.lower()}|{family}|job={job_id}|src={data_source.lower()}"
        if event.crash_type == CrashType.SOLR_CRASH:
            incident_status = str(details.get("incident_status") or "").strip().upper()
            incident_id = str(details.get("incident_id") or "").strip() or "none"
            if incident_status:
                return f"SOLR_CRASH|{incident_status}|{incident_id}"
            return f"SOLR_CRASH|{event.severity.name}"
        if event.crash_type == CrashType.CORRELATED_INCIDENT:
            event_types = event.details.get("event_types") or []
            type_part = ",".join(sorted(str(x).upper() for x in event_types))
            return f"CORRELATED|{type_part or 'unknown'}"
        return f"{event.crash_type.name}|{event.severity.name}"

    def _alert_batch_signature(self, events: list[CrashEvent]) -> str:
        if not events:
            return ""
        if len(events) == 1:
            return self._event_incident_signature(events[0])
        parts = sorted({self._event_incident_signature(e) for e in events})
        sev = "CRITICAL" if any(e.severity == Severity.CRITICAL for e in events) else "WARNING"
        return f"{sev}|BATCH|{'|'.join(parts)}"

    def _refresh_incident_states(self, active_signatures: set[str], now: float) -> None:
        for signature, state in self._incident_state.items():
            if signature in active_signatures:
                continue
            if str(state.get("status") or "") == "RESOLVED":
                continue
            last_seen = float(state.get("last_seen", 0.0))
            if (now - last_seen) >= self._incident_resolve_quiet_seconds:
                state["status"] = "RESOLVED"
                state["resolved_at"] = now

        stale_cutoff = now - max(
            self._warning_reminder_seconds,
            self._critical_reminder_seconds,
            self._incident_resolve_quiet_seconds,
        ) * 6.0
        stale = [k for k, v in self._incident_state.items() if float(v.get("last_seen", 0.0)) < stale_cutoff]
        for key in stale:
            self._incident_state.pop(key, None)

    def _apply_alert_cooldown(self, events: list[CrashEvent], now: float) -> list[CrashEvent]:
        if not events:
            self._refresh_incident_states(set(), now)
            return []

        active_signatures = {self._event_incident_signature(ev) for ev in events}
        self._refresh_incident_states(active_signatures, now)

        emitted: list[CrashEvent] = []
        for event in events:
            signature = self._event_incident_signature(event)
            state = self._incident_state.get(signature)
            reminder_seconds = (
                self._critical_reminder_seconds
                if event.severity == Severity.CRITICAL
                else self._warning_reminder_seconds
            )

            if state is None or str(state.get("status") or "") == "RESOLVED":
                self._incident_state[signature] = {
                    "status": "OPEN",
                    "opened_at": now,
                    "last_seen": now,
                    "last_notified": now,
                    "severity": event.severity.name,
                }
                emitted.append(event)
                continue

            previous_severity = str(state.get("severity") or event.severity.name)
            state["last_seen"] = now
            state["status"] = "ONGOING"

            if previous_severity != event.severity.name:
                state["severity"] = event.severity.name
                state["last_notified"] = now
                emitted.append(event)
                continue

            last_notified = float(state.get("last_notified", 0.0))
            if (now - last_notified) >= reminder_seconds:
                state["last_notified"] = now
                emitted.append(event)
                continue

            logger.info("Suppressing ongoing incident alert: %s", signature)

        return emitted

    @staticmethod
    def _is_shutdown_noise_event(event: CrashEvent) -> bool:
        shutdown_noise_types = {CrashType.SOLR_CRASH, CrashType.LOG_ERROR}
        if event.crash_type in shutdown_noise_types:
            return True
        if event.crash_type != CrashType.CORRELATED_INCIDENT:
            return False
        event_types = event.details.get("event_types") or []
        if not event_types:
            return False
        normalized = {str(x).upper() for x in event_types}
        return normalized.issubset({"SOLR_CRASH", "LOG_ERROR"})

    def _filter_shutdown_noise_alerts(
        self,
        events: list[CrashEvent],
        *,
        now: float,
        pid: int | None,
        lock_exists: bool,
    ) -> list[CrashEvent]:
        if not events:
            return []
        in_shutdown_grace = now <= self._shutdown_noise_grace_until
        case_closing = pid is None and not lock_exists
        if not in_shutdown_grace and not case_closing:
            return events
        if self._log_detector.ingest_running:
            return events

        kept: list[CrashEvent] = []
        suppressed = 0
        for event in events:
            if self._is_shutdown_noise_event(event):
                suppressed += 1
                continue
            kept.append(event)
        if suppressed:
            logger.info(
                "Suppressing %d shutdown-noise alert(s) during graceful close window.",
                suppressed,
            )
        return kept

    @staticmethod
    def _is_nonfatal_solr_ping_event(event: CrashEvent) -> bool:
        if event.crash_type != CrashType.LOG_ERROR or event.severity != Severity.CRITICAL:
            return False
        log_line = str((event.details or {}).get("log_line") or "")
        if _NONFATAL_SOLR_PING_LOG_PATTERN.search(log_line):
            return True
        return False

    def _filter_nonfatal_solr_ping_alerts(self, events: list[CrashEvent]) -> list[CrashEvent]:
        if not events:
            return []
        if not any(self._is_nonfatal_solr_ping_event(ev) for ev in events):
            return events
        try:
            status = self._solr_cache.get_status()
        except Exception:
            status = None
        if status is None or not getattr(status, "is_up", False):
            return events

        kept: list[CrashEvent] = []
        suppressed = 0
        for event in events:
            if self._is_nonfatal_solr_ping_event(event):
                suppressed += 1
                continue
            kept.append(event)
        if suppressed:
            logger.info(
                "Suppressing %d non-fatal Solr ping noise alert(s) while Solr is reachable.",
                suppressed,
            )
        return kept

    @staticmethod
    def _is_confirmed_solr_outage_event(event: CrashEvent) -> bool:
        if event.crash_type != CrashType.SOLR_CRASH:
            return False
        if event.severity == Severity.CRITICAL:
            return True
        low = event.message.lower()
        if "not responding on port" in low:
            return True
        details = event.details or {}
        try:
            failures = int(details.get("failures_in_window", 0))
        except Exception:
            failures = 0
        return failures > 0

    @staticmethod
    def _is_solr_derivative_event(event: CrashEvent) -> bool:
        if event.crash_type != CrashType.LOG_ERROR:
            return False
        details = event.details or {}
        line = str(details.get("line") or details.get("log_line") or "")
        text = f"{event.message} {line}".lower()
        tokens = (
            "unable to send document batch to solr",
            "could not add batched documents to index",
            "keywordsearchmoduleexception",
            "server refused connection",
            "connectexception: connection refused",
            "httphostconnectexception",
            "solrserverexception",
        )
        return any(token in text for token in tokens)

    def _next_incident_id(self, prefix: str) -> str:
        self._incident_sequence += 1
        return f"{prefix}-{self._incident_sequence}"

    def _annotate_solr_incident_details(
        self,
        event: CrashEvent,
        *,
        incident: dict[str, object],
        status: str,
        now: float,
    ) -> None:
        details = dict(event.details or {})
        outage_duration = max(0.0, now - float(incident.get("first_seen", now)))
        details["incident_id"] = str(incident.get("incident_id"))
        details["parent_incident_id"] = str(incident.get("incident_id"))
        details["incident_status"] = status
        details["outage_duration_seconds"] = int(outage_duration)
        details["derivative_suppressed_count"] = int(incident.get("derivative_suppressed_count", 0))
        details["retry_attempt_count"] = int(incident.get("retry_attempt_count", 0))
        details["batch_failure_count"] = int(incident.get("batch_failure_count", 0))
        details["first_seen"] = self._ts_label(float(incident.get("first_seen", now)))
        details["last_seen"] = self._ts_label(float(incident.get("last_seen", now)))
        details["ingest_job_id"] = str(incident.get("ingest_job_id", "unknown"))
        details["data_source"] = str(incident.get("data_source", "unknown"))
        event.details = details

    def _update_solr_outage_derivative_counters(
        self,
        incident: dict[str, object],
        event: CrashEvent,
        *,
        now: float,
    ) -> None:
        details = event.details or {}
        occ = 1
        try:
            occ = max(1, int(details.get("occurrence_count", 1)))
        except Exception:
            occ = 1
        incident["last_seen"] = now
        incident["derivative_suppressed_count"] = int(incident.get("derivative_suppressed_count", 0)) + occ
        text = f"{event.message} {details.get('line') or details.get('log_line') or ''}".lower()
        if "re-trying" in text:
            incident["retry_attempt_count"] = int(incident.get("retry_attempt_count", 0)) + occ
        if "all re-try attempts failed" in text or "could not add batched documents to index" in text:
            incident["batch_failure_count"] = int(incident.get("batch_failure_count", 0)) + occ

    def _resolve_context_from_event(self, event: CrashEvent, *, now: float) -> tuple[str, str]:
        details = event.details or {}
        line = str(details.get("line") or details.get("log_line") or "")
        text = f"{event.message} {line}".strip()
        return self._resolve_context(line_text=text, details=details, now=now)

    def _apply_solr_outage_policy(self, events: list[CrashEvent], *, now: float) -> list[CrashEvent]:
        if not events:
            return []

        kept: list[CrashEvent] = []
        outage = self._solr_outage_incident
        open_event: CrashEvent | None = None
        for event in events:
            if not self._is_confirmed_solr_outage_event(event):
                continue
            if open_event is None:
                open_event = event
            elif event.severity == Severity.CRITICAL and open_event.severity != Severity.CRITICAL:
                open_event = event

        if open_event is not None:
            ingest_job_id, data_source = self._resolve_context_from_event(open_event, now=now)
            if outage is None or str(outage.get("status") or "") == "RESOLVED":
                outage = {
                    "incident_id": self._next_incident_id("solr-outage"),
                    "status": "OPEN",
                    "first_seen": now,
                    "last_seen": now,
                    "ingest_job_id": ingest_job_id,
                    "data_source": data_source,
                    "retry_attempt_count": 0,
                    "batch_failure_count": 0,
                    "derivative_suppressed_count": 0,
                }
                self._solr_outage_incident = outage
            else:
                outage["status"] = "OPEN"
                outage["last_seen"] = now
                if self._normalize_context_value(outage.get("ingest_job_id")) is None and ingest_job_id != "unknown":
                    outage["ingest_job_id"] = ingest_job_id
                if self._normalize_context_value(outage.get("data_source")) is None and data_source != "unknown":
                    outage["data_source"] = data_source
            self._remember_context(ingest_job_id, data_source, now=now)
            self._annotate_solr_incident_details(open_event, incident=outage, status="OPEN", now=now)

        for event in events:
            if event is open_event:
                kept.append(event)
                continue
            if self._is_confirmed_solr_outage_event(event):
                continue

            if outage is not None and str(outage.get("status") or "") == "OPEN" and self._is_solr_derivative_event(event):
                self._update_solr_outage_derivative_counters(outage, event, now=now)
                logger.info(
                    "Suppressing derivative Solr/Keyword warning while outage incident %s is open.",
                    str(outage.get("incident_id")),
                )
                continue
            kept.append(event)

        return kept

    def _solr_currently_healthy(self) -> bool:
        try:
            status = self._solr_cache.get_status()
        except Exception:
            return False
        return bool(status and getattr(status, "is_up", False))

    def _maybe_build_solr_outage_recovery_alert(self, *, now: float) -> CrashEvent | None:
        outage = self._solr_outage_incident
        if outage is None:
            return None
        if str(outage.get("status") or "") != "OPEN":
            return None
        if not self._solr_currently_healthy():
            return None
        last_seen = float(outage.get("last_seen", 0.0))
        if (now - last_seen) < self._solr_outage_resolve_quiet_seconds:
            return None

        outage["status"] = "RESOLVED"
        outage["resolved_at"] = now
        duration = max(0.0, now - float(outage.get("first_seen", now)))
        event = CrashEvent(
            crash_type=CrashType.SOLR_CRASH,
            severity=Severity.WARNING,
            message="Solr outage recovered; service is reachable again.",
            details={},
        )
        self._annotate_solr_incident_details(event, incident=outage, status="RESOLVED", now=now)
        event.details["outage_duration_seconds"] = int(duration)
        return event

    def _solr_outage_telemetry_snapshot(self, *, now: float) -> dict[str, object] | None:
        outage = self._solr_outage_incident
        if outage is None:
            return None
        first_seen = float(outage.get("first_seen", now))
        last_seen = float(outage.get("last_seen", now))
        status = str(outage.get("status") or "UNKNOWN").upper()
        snapshot: dict[str, object] = {
            "incident_id": str(outage.get("incident_id") or ""),
            "incident_status": status,
            "first_seen": self._ts_label(first_seen),
            "last_seen": self._ts_label(last_seen),
            "outage_duration_seconds": int(max(0.0, now - first_seen)),
            "retry_attempt_count": int(outage.get("retry_attempt_count", 0)),
            "batch_failure_count": int(outage.get("batch_failure_count", 0)),
            "derivative_suppressed_count": int(outage.get("derivative_suppressed_count", 0)),
            "ingest_job_id": str(outage.get("ingest_job_id", "unknown")),
            "data_source": str(outage.get("data_source", "unknown")),
        }
        if "resolved_at" in outage:
            snapshot["resolved_at"] = self._ts_label(float(outage.get("resolved_at", now)))
        return snapshot

    @staticmethod
    def _event_epoch(event: CrashEvent, now: float) -> float:
        try:
            return float(event.timestamp.timestamp())
        except Exception:
            return now

    @staticmethod
    def _ts_label(epoch: float | None) -> str | None:
        if epoch is None:
            return None
        try:
            return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return None

    def _parse_log_error_context(self, event: CrashEvent) -> dict[str, str] | None:
        if event.crash_type != CrashType.LOG_ERROR:
            return None
        details = event.details or {}
        line = str(details.get("line") or details.get("log_line") or "")
        text = f"{event.message} {line}".strip()
        low = text.lower()
        signature = self._extract_signature_family(text)
        now = self._event_epoch(event, time.time())
        ingest_job_id, data_source = self._resolve_context(
            line_text=text,
            details=details,
            now=now,
        )
        module = str(details.get("module") or self._extract_signature_module(text))
        if module.lower() == "general":
            inferred = self._module_from_signature_family(signature, text)
            if inferred:
                module = inferred
            else:
                anchored = self._module_from_recent_anchor(
                    ingest_job_id=ingest_job_id,
                    data_source=data_source,
                    now=now,
                )
                if anchored:
                    module = anchored
        self._anchor_module_for_context(
            ingest_job_id=ingest_job_id,
            data_source=data_source,
            module=module,
            now=now,
        )
        source_file = str(details.get("file") or "").strip().lower()
        return {
            "incident_key": (
                f"logerr|module={module.lower()}|sig={signature}|"
                f"job={ingest_job_id or 'unknown'}|src={data_source or 'unknown'}"
            ),
            "signature": signature,
            "ingest_job_id": ingest_job_id or "unknown",
            "data_source": data_source or "unknown",
            "line": line or event.message,
            "module": module,
            "is_keyword": "keyword search" in low or "keywordsearch" in low,
            "source_file": source_file,
        }

    @staticmethod
    def _is_report_only_log_signature(context: dict[str, str], text: str) -> bool:
        low = text.lower()
        if context.get("signature") != "illegal_argument":
            return False
        if not _NON_ACTIONABLE_VENDOR_NULL_PATTERN.search(low):
            return False
        source_file = str(context.get("source_file") or "")
        return source_file.endswith("messages.log")

    @staticmethod
    def _extract_first_match(pattern: re.Pattern[str], text: str) -> str | None:
        match = pattern.search(text)
        if not match:
            return None
        value = (match.group(1) or "").strip()
        return value or None

    def _prune_log_error_incidents(self, now: float) -> None:
        cutoff = now - self._log_error_incident_ttl_seconds
        stale = [
            key
            for key, value in self._log_error_incidents.items()
            if float(value.get("last_seen", 0.0)) < cutoff
        ]
        for key in stale:
            self._log_error_incidents.pop(key, None)

    def _aggregate_log_error_alerts(self, events: list[CrashEvent], *, now: float) -> list[CrashEvent]:
        if not events:
            return []
        self._prune_log_error_incidents(now)
        aggregated: list[CrashEvent] = []
        for event in events:
            context = self._parse_log_error_context(event)
            if context is None:
                aggregated.append(event)
                continue
            # Keyword Search has a dedicated aggregator that merges special
            # stack-trace families into a single incident summary.
            if context.get("is_keyword"):
                aggregated.append(event)
                continue

            event_epoch = self._event_epoch(event, now)
            key = context["incident_key"]
            is_report_only = self._is_report_only_log_signature(context, f"{event.message} {context.get('line','')}")
            existing = self._log_error_incidents.get(key)
            if existing is None:
                existing = {
                    **context,
                    "first_seen": event_epoch,
                    "last_seen": event_epoch,
                    "occurrence_count": 1,
                    "report_only": bool(is_report_only),
                }
                self._log_error_incidents[key] = existing
                self._record_module_error_summary(existing)
                if is_report_only:
                    logger.info(
                        "Suppressing known non-actionable log warning from immediate alerts: %s",
                        context["line"][:140],
                    )
                    continue
                aggregated.append(
                    CrashEvent(
                        crash_type=CrashType.LOG_ERROR,
                        severity=event.severity,
                        message=(
                            f"{context['module']} log error burst detected "
                            f"(signature={context['signature']}, job={context['ingest_job_id']}, "
                            f"source={context['data_source']}). Repeated lines are aggregated."
                        ),
                        details={
                            "module": context["module"],
                            "aggregated_incident": True,
                            "occurrence_count": 1,
                            "first_seen": self._ts_label(event_epoch),
                            "last_seen": self._ts_label(event_epoch),
                            "signature": context["signature"],
                            "ingest_job_id": context["ingest_job_id"],
                            "data_source": context["data_source"],
                            "line": context["line"],
                            "file": event.details.get("file"),
                            "line_number": event.details.get("line_number"),
                        },
                    )
                )
            else:
                existing["last_seen"] = event_epoch
                existing["occurrence_count"] = int(existing.get("occurrence_count", 0)) + 1
                self._record_module_error_summary(existing)
                if is_report_only or bool(existing.get("report_only")):
                    continue
        return aggregated

    def _keyword_context(self, event: CrashEvent) -> dict[str, str] | None:
        if event.crash_type != CrashType.LOG_ERROR:
            return None

        details = event.details or {}
        line = str(details.get("line") or details.get("log_line") or "")
        haystack = f"{event.message} {line}".strip()
        low = haystack.lower()

        keyword_markers = (
            "keyword search",
            "keywordsearch",
            "org.sleuthkit.autopsy.keywordsearch",
            "codermalfunctionerror",
            "arrayindexoutofboundsexception",
        )
        if not any(marker in low for marker in keyword_markers):
            return None

        if "arrayindexoutofboundsexception" in low:
            signature = "arrayindexoutofboundsexception"
        elif "codermalfunctionerror" in low:
            signature = "codermalfunctionerror"
        elif "experienced an error during analysis" in low:
            signature = "analysis_error"
        else:
            signature = "keyword_error"

        burst_family = signature
        # These stack-trace lines are part of one logical Keyword Search
        # ingest-failure burst and should stay in a single incident thread.
        if signature in {"analysis_error", "codermalfunctionerror", "arrayindexoutofboundsexception"}:
            burst_family = "keyword_ingest_exception_burst"

        event_epoch = self._event_epoch(event, time.time())
        ingest_job_id, data_source = self._resolve_context(
            line_text=haystack,
            details=details,
            now=event_epoch,
        )
        self._anchor_module_for_context(
            ingest_job_id=ingest_job_id,
            data_source=data_source,
            module="Keyword Search",
            now=event_epoch,
        )
        object_id = self._extract_first_match(_OBJECT_ID_PATTERN, haystack)
        incident_key = (
            f"keyword|job={ingest_job_id}|src={data_source}|sig={burst_family}"
        )
        return {
            "incident_key": incident_key,
            "signature": signature,
            "signature_family": burst_family,
            "ingest_job_id": ingest_job_id,
            "data_source": data_source,
            "object_id": object_id or "unknown",
            "line": line or event.message,
            "module": "Keyword Search",
            "file": details.get("file"),
            "line_number": details.get("line_number"),
        }

    def _record_module_error_summary(self, incident: dict[str, object]) -> None:
        summary_key = str(incident["incident_key"])
        signatures = incident.get("signatures")
        if isinstance(signatures, set) and signatures:
            signature_text = ",".join(sorted(str(x) for x in signatures))
        else:
            signature_text = str(incident.get("signature") or "keyword_error")
        self._module_error_summary_since_report[summary_key] = {
            "module": str(incident["module"]),
            "signature": signature_text,
            "ingest_job_id": str(incident["ingest_job_id"]),
            "data_source": str(incident["data_source"]),
            "occurrence_count": int(incident["occurrence_count"]),
            "first_seen": self._ts_label(float(incident["first_seen"])),
            "last_seen": self._ts_label(float(incident["last_seen"])),
            "state": "error",
        }

    def _prune_keyword_incidents(self, now: float) -> None:
        cutoff = now - self._keyword_incident_ttl_seconds
        stale = [
            key
            for key, value in self._keyword_incidents.items()
            if float(value.get("last_seen", 0.0)) < cutoff
        ]
        for key in stale:
            self._keyword_incidents.pop(key, None)

    def _find_recent_keyword_incident_key(self, now: float, *, max_age_seconds: float = 120.0) -> str | None:
        winner_key: str | None = None
        winner_ts = 0.0
        cutoff = now - max_age_seconds
        for key, incident in self._keyword_incidents.items():
            last_seen = float(incident.get("last_seen", 0.0))
            if last_seen < cutoff:
                continue
            if last_seen >= winner_ts:
                winner_ts = last_seen
                winner_key = key
        return winner_key

    def _aggregate_keyword_search_alerts(self, events: list[CrashEvent], *, now: float) -> list[CrashEvent]:
        if not events:
            return []

        self._prune_keyword_incidents(now)
        aggregated: list[CrashEvent] = []
        for event in events:
            context = self._keyword_context(event)
            if context is None:
                aggregated.append(event)
                continue

            event_epoch = self._event_epoch(event, now)
            key = context["incident_key"]
            if context.get("ingest_job_id") == "unknown" and context.get("data_source") == "unknown":
                fallback_key = self._find_recent_keyword_incident_key(event_epoch)
                if fallback_key:
                    key = fallback_key
            existing = self._keyword_incidents.get(key)
            if existing is None:
                existing = {
                    **context,
                    "first_seen": event_epoch,
                    "last_seen": event_epoch,
                    "occurrence_count": 1,
                    "signatures": {context["signature"]},
                }
                self._keyword_incidents[key] = existing
                summary_event = CrashEvent(
                    crash_type=CrashType.LOG_ERROR,
                    severity=Severity.WARNING,
                    message=(
                        "Keyword Search error burst detected "
                        f"(signature={context['signature']}, job={context['ingest_job_id']}, "
                        f"source={context['data_source']}). Repeated lines are aggregated."
                    ),
                    details={
                        "module": "Keyword Search",
                        "aggregated_incident": True,
                        "occurrence_count": 1,
                        "first_seen": self._ts_label(event_epoch),
                        "last_seen": self._ts_label(event_epoch),
                        "signature": context["signature"],
                        "ingest_job_id": context["ingest_job_id"],
                        "data_source": context["data_source"],
                        "object_id": context["object_id"],
                        "line": context["line"],
                        "file": context.get("file"),
                        "line_number": context.get("line_number"),
                    },
                )
                aggregated.append(summary_event)
            else:
                existing["last_seen"] = event_epoch
                existing["occurrence_count"] = int(existing.get("occurrence_count", 0)) + 1
                signatures = existing.get("signatures")
                if isinstance(signatures, set):
                    signatures.add(context["signature"])
                elif isinstance(signatures, list):
                    signatures.append(context["signature"])
                    existing["signatures"] = set(signatures)
                else:
                    existing["signatures"] = {str(existing.get("signature") or "keyword_error"), context["signature"]}

            self._record_module_error_summary(self._keyword_incidents[key])

        return aggregated

    def _inject_module_error_summary(self, telemetry: dict[str, object]) -> None:
        telemetry["module_errors_summary"] = []
        if not self._module_error_summary_since_report:
            return
        summary_items = sorted(
            self._module_error_summary_since_report.values(),
            key=lambda item: str(item.get("last_seen") or ""),
            reverse=True,
        )
        telemetry["module_errors_summary"] = summary_items
        module_activity = telemetry.get("module_activity")
        if isinstance(module_activity, list):
            for item in summary_items[:3]:
                module_activity.insert(
                    0,
                    {
                        "module": item.get("module", "Keyword Search"),
                        "state": "error",
                        "timestamp": item.get("last_seen"),
                        "line": (
                            f"Aggregated errors: signature={item.get('signature')} | "
                            f"occurrences={item.get('occurrence_count')} | "
                            f"job={item.get('ingest_job_id')}"
                        ),
                    },
                )

    def _filter_post_ingest_resource_alerts(self, events: list[CrashEvent], *, now: float) -> list[CrashEvent]:
        if not events:
            return []
        if self._log_detector.ingest_running or now > self._post_ingest_resource_grace_until:
            return events

        kept: list[CrashEvent] = []
        suppressed = 0
        for event in events:
            if event.crash_type == CrashType.HIGH_RESOURCE_USAGE:
                suppressed += 1
                continue
            kept.append(event)
        if suppressed:
            remaining = max(0.0, self._post_ingest_resource_grace_until - now)
            logger.info(
                "Suppressing %d post-ingest resource alert(s) during grace window (%.0fs left).",
                suppressed,
                remaining,
            )
        return kept

    def _event_module_identity(self, event: CrashEvent) -> str | None:
        details = event.details or {}
        module = str(details.get("module") or "").strip()
        if module:
            return module
        line = str(details.get("line") or details.get("log_line") or "")
        payload = f"{event.message} {line}".strip()
        guessed = self._extract_signature_module(payload)
        return guessed if guessed != "General" else None

    def _build_module_period_counters(self, events: list[CrashEvent]) -> dict[str, dict[str, int]]:
        counters: dict[str, dict[str, int]] = {}
        for event in events:
            module = self._event_module_identity(event)
            if not module:
                continue
            key = module.strip().lower()
            row = counters.setdefault(key, {"activity": 0, "errors": 0})
            row["activity"] += 1
            if event.crash_type == CrashType.LOG_ERROR:
                row["errors"] += 1
        return counters

    def _should_throttle_console_event(self, event: CrashEvent) -> bool:
        if event.severity != Severity.WARNING:
            return False
        return event.crash_type in {CrashType.LOG_ERROR, CrashType.SOLR_CRASH}

    def _flush_console_event_summaries(self, *, now: float, force: bool = False) -> None:
        if not self._console_log_suppression:
            return
        stale_cutoff = now - max(
            self._console_summary_idle_seconds,
            self._console_repeat_window_seconds,
        )
        stale_keys: list[str] = []
        for signature, state in self._console_log_suppression.items():
            suppressed = int(state.get("suppressed", 0))
            last_seen = float(state.get("last_seen", 0.0))
            crash_type = str(state.get("crash_type") or "LOG_ERROR")
            burst_tag = "LOG_ERROR_BURST" if crash_type == "LOG_ERROR" else "SOLR_CRASH_BURST"
            if suppressed > 0 and (force or last_seen <= stale_cutoff):
                latest_message = str(state.get("message") or "")
                logger.warning(
                    "🟡 %s: Suppressed %d repeated warning event(s) for %s. Latest: %s",
                    burst_tag,
                    suppressed,
                    signature,
                    latest_message,
                )
                state["suppressed"] = 0
            if force or (last_seen <= stale_cutoff and int(state.get("suppressed", 0)) == 0):
                stale_keys.append(signature)
        for key in stale_keys:
            self._console_log_suppression.pop(key, None)

    def _handle_event(self, event: CrashEvent) -> None:
        """Log detected events with console-side burst suppression for repeated warning log errors."""
        now = time.time()
        if self._should_throttle_console_event(event):
            signature = self._event_incident_signature(event)
            state = self._console_log_suppression.get(signature)
            if state is None:
                self._console_log_suppression[signature] = {
                    "last_emit": now,
                    "last_seen": now,
                    "suppressed": 0,
                    "message": event.message,
                    "crash_type": event.crash_type.name,
                }
            else:
                last_emit = float(state.get("last_emit", 0.0))
                state["last_seen"] = now
                state["message"] = event.message
                if (now - last_emit) < self._console_repeat_window_seconds:
                    state["suppressed"] = int(state.get("suppressed", 0)) + 1
                    return
                suppressed = int(state.get("suppressed", 0))
                crash_type = str(state.get("crash_type") or event.crash_type.name)
                burst_tag = "LOG_ERROR_BURST" if crash_type == "LOG_ERROR" else "SOLR_CRASH_BURST"
                if suppressed > 0:
                    logger.warning(
                        "🟡 %s: Suppressed %d repeated warning event(s) for %s.",
                        burst_tag,
                        suppressed,
                        signature,
                    )
                    state["suppressed"] = 0
                state["last_emit"] = now

        severity_icon = "🔴" if event.severity.name == "CRITICAL" else "🟡"
        logger.warning(
            "%s %s: %s", 
            severity_icon, 
            event.crash_type.name, 
            event.message
        )

    @staticmethod
    def _parse_report_timestamp(value: object) -> float | None:
        text = str(value or "").strip()
        if not text:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(text[:19], fmt).timestamp()
            except Exception:
                continue
        return None

    def _has_recent_module_folder_activity(
        self,
        module_folders: object,
        *,
        now_ts: float | None = None,
        max_age_seconds: float = 1800.0,
    ) -> bool:
        if not isinstance(module_folders, list):
            return False
        now = now_ts if now_ts is not None else time.time()
        markers = ("keyword", "solr", "photorec", "carver", "search")
        for folder in module_folders:
            if not isinstance(folder, dict):
                continue
            name = str(folder.get("name") or "").lower()
            if not any(marker in name for marker in markers):
                continue
            updated_ts = self._parse_report_timestamp(folder.get("updated_at"))
            if updated_ts is None:
                continue
            if (now - updated_ts) <= max_age_seconds:
                return True
        return False

    def _has_forensic_background_signals(self, telemetry: dict[str, object]) -> bool:
        """Detect Keyword Search / Solr style work without an active ingest job."""
        module_activity = telemetry.get("module_activity") or []
        if isinstance(module_activity, list) and module_activity:
            return True

        summary = telemetry.get("module_activity_summary") or []
        if isinstance(summary, list):
            for item in summary:
                if not isinstance(item, dict):
                    continue
                module_name = str(item.get("module_name") or item.get("module") or "").lower()
                if any(token in module_name for token in ("keyword", "solr", "photorec", "carver")):
                    return True

        if self._has_recent_module_folder_activity(telemetry.get("module_folders")):
            return True

        solr = telemetry.get("solr") or {}
        if not isinstance(solr, dict):
            return False
        if str(solr.get("state", "")).lower() != "up":
            return False

        try:
            if solr.get("response_time_seconds") is not None and float(solr["response_time_seconds"]) >= 0.0:
                return True
        except Exception:
            pass
        try:
            if float(solr.get("heap_usage_percent") or 0.0) >= 15.0:
                return True
        except Exception:
            pass
        try:
            if float(solr.get("cpu_percent") or 0.0) >= 5.0:
                return True
        except Exception:
            pass
        return False

    def _classify_runtime_status(self, telemetry: dict[str, object]) -> str:
        """Classify runtime state for periodic human-facing reports."""
        if self._log_detector.ingest_running:
            return "PROCESSING"

        if self._has_forensic_background_signals(telemetry):
            return "ACTIVE_NON_INGEST"

        cpu_now = None
        try:
            cpu_now = (telemetry.get("autopsy_cpu_timeline") or {}).get("current")
        except Exception:
            cpu_now = None

        cpu_threshold = max(2.0, float(self.config.hang_cpu_threshold))
        if cpu_now is not None:
            try:
                if float(cpu_now) >= cpu_threshold:
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

