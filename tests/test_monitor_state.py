from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from autopsyguard.config import MonitorConfig
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
