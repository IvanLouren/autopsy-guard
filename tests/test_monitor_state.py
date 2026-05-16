from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.monitor import Monitor, MonitorState
from autopsyguard.utils.solr_health import SolrStatus


def make_config(tmp_path: Path) -> MonitorConfig:
    return MonitorConfig(case_dir=tmp_path)


def test_waiting_to_active(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)

    # Create the case Log lock file expected by get_case_lock_file()
    log_dir = tmp_path / "Log"
    log_dir.mkdir()
    lock_file = log_dir / "autopsy.log.0.lck"
    lock_file.write_text("")

    with patch("autopsyguard.monitor.find_autopsy_pid", return_value=123):
        # The monitor should transition to ACTIVE when _handle_waiting runs
        monitor._state = MonitorState.WAITING
        monitor._handle_waiting()
        assert monitor._state == MonitorState.ACTIVE


def test_startup_notification_sent_on_autopsy_detect(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    called = {"email": 0, "wa": 0, "tg": 0}
    monitor.notifier.send_startup_message = lambda: called.__setitem__("email", called["email"] + 1) or True
    monitor.whatsapp.send_startup_message = lambda: called.__setitem__("wa", called["wa"] + 1) or True
    monitor.telegram.send_startup_message = lambda: called.__setitem__("tg", called["tg"] + 1) or True

    with patch("autopsyguard.monitor.find_autopsy_pid", return_value=123):
        monitor._state = MonitorState.WAITING
        monitor._handle_waiting()
        assert monitor._state == MonitorState.ACTIVE
    assert called == {"email": 1, "wa": 1, "tg": 1}


def test_active_to_finished_on_shutdown(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)

    # Ensure metrics_store.record_sample is a no-op and detectors do not throw
    monitor._metrics_store.record_sample = lambda: None
    monitor.run_once = lambda: []

    # Start in ACTIVE state; simulate Autopsy process gone and no lock file
    monitor._state = MonitorState.ACTIVE
    with patch("autopsyguard.monitor.find_autopsy_pid", return_value=None):
        # Ensure no lock files exist
        # Call _handle_active which should set state to FINISHED when pid is None and no lock
        monitor._handle_active()
        assert monitor._state == MonitorState.FINISHED


def test_priority_alert_flushes_immediately(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    now = 1000.0

    event = CrashEvent(
        crash_type=CrashType.SOLR_CRASH,
        severity=Severity.WARNING,
        message="Solr refused connection",
    )
    ready = monitor._collect_alert_notifications([event], now)
    assert len(ready) == 1


def test_non_priority_alert_respects_correlation_window(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    cfg.poll_interval = 30.0
    monitor = Monitor(cfg)
    now = 2000.0

    event = CrashEvent(
        crash_type=CrashType.LOG_ERROR,
        severity=Severity.WARNING,
        message="Generic warning",
    )
    # First cycle should buffer.
    ready = monitor._collect_alert_notifications([event], now)
    assert ready == []

    # Before window expiry, still buffered.
    ready = monitor._collect_alert_notifications([], now + 30.0)
    assert ready == []

    # After expiry, alert should flush.
    ready = monitor._collect_alert_notifications([], now + 61.0)
    assert len(ready) == 1


def test_classify_runtime_status_active_non_ingest_for_keyword_activity(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    monitor._log_detector._ingest_running = False

    telemetry = {
        "autopsy_cpu_timeline": {"current": 2.0},
        "module_activity": [{"module": "Keyword Search", "state": "active", "line": "..."},],
        "solr": {"state": "up", "response_time_seconds": 0.2},
    }
    assert monitor._classify_runtime_status(telemetry) == "ACTIVE_NON_INGEST"


def test_classify_runtime_status_idle_when_no_activity(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    monitor._log_detector._ingest_running = False

    telemetry = {
        "autopsy_cpu_timeline": {"current": 1.0},
        "module_activity": [],
        "solr": {"state": "unknown", "response_time_seconds": None},
    }
    assert monitor._classify_runtime_status(telemetry) == "IDLE"


def test_pre_ingest_warmup_filters_solr_and_log_warnings(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    monitor._state = MonitorState.ACTIVE
    monitor._metrics_store.record_sample = lambda: None
    monitor._log_detector._ingest_running = False
    monitor._has_ingest_started_ever = False

    warmup_events = [
        CrashEvent(
            crash_type=CrashType.LOG_ERROR,
            severity=Severity.WARNING,
            message="Solr log error in solr.log.7",
        ),
        CrashEvent(
            crash_type=CrashType.SOLR_CRASH,
            severity=Severity.WARNING,
            message="Child Java process disappeared",
        ),
    ]
    monitor.run_once = lambda: warmup_events

    handled: list[CrashEvent] = []
    monitor._handle_event = lambda ev: handled.append(ev)
    monitor.notifier.send_alert = lambda *_args, **_kwargs: True
    monitor.whatsapp.send_alert = lambda *_args, **_kwargs: True
    monitor.telegram.send_alert = lambda *_args, **_kwargs: True

    with patch("autopsyguard.monitor.find_autopsy_pid", return_value=123):
        monitor._handle_active()

    assert handled == []


def test_pre_ingest_warmup_filters_critical_solr_log_noise(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    monitor._state = MonitorState.ACTIVE
    monitor._metrics_store.record_sample = lambda: None
    monitor._log_detector._ingest_running = False
    monitor._has_ingest_started_ever = False

    warmup_events = [
        CrashEvent(
            crash_type=CrashType.LOG_ERROR,
            severity=Severity.CRITICAL,
            message="Solr log error in solr.log.7",
        ),
    ]
    monitor.run_once = lambda: warmup_events

    handled: list[CrashEvent] = []
    monitor._handle_event = lambda ev: handled.append(ev)
    monitor.notifier.send_alert = lambda *_args, **_kwargs: True
    monitor.whatsapp.send_alert = lambda *_args, **_kwargs: True
    monitor.telegram.send_alert = lambda *_args, **_kwargs: True

    with patch("autopsyguard.monitor.find_autopsy_pid", return_value=123):
        monitor._handle_active()

    assert handled == []


def test_shutdown_grace_suppresses_post_ingest_solr_noise_alerts(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    monitor._state = MonitorState.ACTIVE
    monitor._metrics_store.record_sample = lambda: None
    monitor._has_ingest_started_ever = True
    monitor._was_ingest_running = True
    monitor._ingest_start_time = 100.0
    monitor._log_detector._ingest_running = False
    monitor.notifier.send_ingest_report = lambda *_args, **_kwargs: True
    monitor.whatsapp.send_ingest_report = lambda *_args, **_kwargs: True
    monitor.telegram.send_ingest_report = lambda *_args, **_kwargs: True

    events = [
        CrashEvent(
            crash_type=CrashType.SOLR_CRASH,
            severity=Severity.WARNING,
            message="Child Java process disappeared",
        ),
        CrashEvent(
            crash_type=CrashType.LOG_ERROR,
            severity=Severity.CRITICAL,
            message="Solr log error in solr.log.stderr",
        ),
    ]
    monitor.run_once = lambda: events

    sent: list[list[CrashEvent]] = []
    monitor.notifier.send_alert = lambda payload: sent.append(payload) or True
    monitor.whatsapp.send_alert = lambda *_args, **_kwargs: True
    monitor.telegram.send_alert = lambda *_args, **_kwargs: True

    with patch("autopsyguard.monitor.find_autopsy_pid", return_value=123):
        monitor._handle_active()

    assert sent == []
    assert monitor._shutdown_noise_grace_until > 0


def test_shutdown_grace_does_not_suppress_true_crash_signals(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    monitor._state = MonitorState.ACTIVE
    monitor._metrics_store.record_sample = lambda: None
    monitor._has_ingest_started_ever = True
    monitor._log_detector._ingest_running = False
    monitor._shutdown_noise_grace_until = 9999999999.0

    event = CrashEvent(
        crash_type=CrashType.PROCESS_DISAPPEARED,
        severity=Severity.CRITICAL,
        message="Autopsy disappeared",
    )
    monitor.run_once = lambda: [event]

    sent: list[list[CrashEvent]] = []
    monitor.notifier.send_alert = lambda payload: sent.append(payload) or True
    monitor.whatsapp.send_alert = lambda *_args, **_kwargs: True
    monitor.telegram.send_alert = lambda *_args, **_kwargs: True

    with patch("autopsyguard.monitor.find_autopsy_pid", return_value=123):
        monitor._handle_active()

    assert len(sent) == 1
    assert sent[0][0].crash_type == CrashType.PROCESS_DISAPPEARED


def test_nonfatal_solr_ping_noise_filtered_when_solr_is_up(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    monitor._solr_cache.get_status = lambda: SolrStatus(
        is_up=True,
        response_time=0.1,
        checked_at=1.0,
        error=None,
    )
    ev = CrashEvent(
        crash_type=CrashType.LOG_ERROR,
        severity=Severity.CRITICAL,
        message="Solr log error in solr.log",
        details={
            "log_line": "org.apache.solr.common.SolrException: Unknown RequestHandler (qt): search",
        },
    )
    assert monitor._filter_nonfatal_solr_ping_alerts([ev]) == []


def test_nonfatal_solr_ping_noise_not_filtered_when_solr_is_down(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    monitor._solr_cache.get_status = lambda: SolrStatus(
        is_up=False,
        response_time=None,
        checked_at=1.0,
        error="Connection refused",
    )
    ev = CrashEvent(
        crash_type=CrashType.LOG_ERROR,
        severity=Severity.CRITICAL,
        message="Solr log error in solr.log",
        details={
            "log_line": "org.apache.solr.common.SolrException: Unknown RequestHandler (qt): search",
        },
    )
    kept = monitor._filter_nonfatal_solr_ping_alerts([ev])
    assert len(kept) == 1
    assert kept[0].crash_type == CrashType.LOG_ERROR


def test_keyword_error_burst_is_aggregated_into_single_alert(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    now = 1000.0
    events = [
        CrashEvent(
            crash_type=CrashType.LOG_ERROR,
            severity=Severity.WARNING,
            message="SEVERE error in autopsy.log.0",
            details={
                "line": "SEVERE: Keyword Search experienced an error during analysis while processing file foo.dll (object ID = 11365) (data source = image.E01, ingest job ID = 7)"
            },
        ),
        CrashEvent(
            crash_type=CrashType.LOG_ERROR,
            severity=Severity.WARNING,
            message="Exception detected in autopsy.log.0",
            details={"line": "java.nio.charset.CoderMalfunctionError: java.lang.ArrayIndexOutOfBoundsException"},
        ),
        CrashEvent(
            crash_type=CrashType.LOG_ERROR,
            severity=Severity.WARNING,
            message="Exception detected in autopsy.log.0",
            details={"line": "java.lang.ArrayIndexOutOfBoundsException: Index -87 out of bounds for length 128"},
        ),
    ]

    aggregated = monitor._aggregate_keyword_search_alerts(events, now=now)
    assert len(aggregated) == 1
    assert aggregated[0].crash_type == CrashType.LOG_ERROR
    assert aggregated[0].details.get("aggregated_incident") is True
    assert "Keyword Search error burst detected" in aggregated[0].message

    summary = list(monitor._module_error_summary_since_report.values())
    assert len(summary) == 1
    assert summary[0]["module"] == "Keyword Search"
    assert int(summary[0]["occurrence_count"]) == 3


def test_post_ingest_resource_alerts_suppressed_inside_grace_window(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    monitor._log_detector._ingest_running = False
    monitor._post_ingest_resource_grace_until = 1000.0
    now = 950.0
    events = [
        CrashEvent(
            crash_type=CrashType.HIGH_RESOURCE_USAGE,
            severity=Severity.WARNING,
            message="Autopsy sustained CPU at 220%",
        ),
        CrashEvent(
            crash_type=CrashType.SOLR_CRASH,
            severity=Severity.CRITICAL,
            message="Solr disappeared",
        ),
    ]

    filtered = monitor._filter_post_ingest_resource_alerts(events, now=now)
    assert len(filtered) == 1
    assert filtered[0].crash_type == CrashType.SOLR_CRASH


def test_post_ingest_resource_alerts_emit_after_grace_window(tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    monitor = Monitor(cfg)
    monitor._log_detector._ingest_running = False
    monitor._post_ingest_resource_grace_until = 1000.0
    event = CrashEvent(
        crash_type=CrashType.HIGH_RESOURCE_USAGE,
        severity=Severity.WARNING,
        message="Autopsy sustained CPU at 220%",
    )

    filtered = monitor._filter_post_ingest_resource_alerts([event], now=1001.0)
    assert len(filtered) == 1
    assert filtered[0].crash_type == CrashType.HIGH_RESOURCE_USAGE
