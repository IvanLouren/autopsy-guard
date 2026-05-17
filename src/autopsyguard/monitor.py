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

        # Check if Autopsy shut down gracefully (process gone + lock removed)
        if pid is None and not lock_exists:
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
        module = str(details.get("module") or self._extract_signature_module(text))
        signature = self._extract_signature_family(text)
        source_file = str(details.get("file") or "").strip().lower()
        ingest_job_id = self._extract_first_match(_INGEST_JOB_ID_PATTERN, text) or str(
            details.get("ingest_job_id") or "unknown"
        )
        data_source = self._extract_first_match(_DATA_SOURCE_PATTERN, text) or str(
            details.get("data_source") or "unknown"
        )
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

        ingest_job_id = self._extract_first_match(_INGEST_JOB_ID_PATTERN, haystack)
        data_source = self._extract_first_match(_DATA_SOURCE_PATTERN, haystack)
        object_id = self._extract_first_match(_OBJECT_ID_PATTERN, haystack)
        incident_key = (
            f"keyword|job={ingest_job_id or 'unknown'}|"
            f"src={data_source or 'unknown'}|sig={signature}"
        )
        return {
            "incident_key": incident_key,
            "signature": signature,
            "ingest_job_id": ingest_job_id or "unknown",
            "data_source": data_source or "unknown",
            "object_id": object_id or "unknown",
            "line": line or event.message,
            "module": "Keyword Search",
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

