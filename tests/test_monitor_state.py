from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.monitor import Monitor, MonitorState


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
