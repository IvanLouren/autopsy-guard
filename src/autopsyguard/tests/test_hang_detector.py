"""Tests for HangDetector."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.hang_detector import HangDetector
from autopsyguard.models import CrashType, Severity


class TestCpuHangDetection:
    """Crash type 4: process alive but CPU near zero for too long."""

    def test_low_cpu_triggers_hang_after_timeout(self, config: MonitorConfig) -> None:
        """CPU at 0% beyond hang_timeout should fire a WARNING."""
        config.hang_timeout = 0.0  # immediate for testing

        detector = HangDetector(config)

        with patch.object(HangDetector, "_find_autopsy_pid", return_value=1000):
            with patch("autopsyguard.detectors.hang_detector.psutil") as mock_psutil:
                proc = MagicMock()
                proc.cpu_percent.return_value = 0.0
                mock_psutil.Process.return_value = proc

                events = detector.check()

        hang_events = [e for e in events if e.crash_type == CrashType.HANG]
        assert len(hang_events) == 1
        assert hang_events[0].severity == Severity.WARNING
        assert "possible hang" in hang_events[0].message.lower()

    def test_normal_cpu_no_hang(self, config: MonitorConfig) -> None:
        """Active CPU should not trigger a hang."""
        detector = HangDetector(config)

        with patch.object(HangDetector, "_find_autopsy_pid", return_value=1000):
            with patch("autopsyguard.detectors.hang_detector.psutil") as mock_psutil:
                proc = MagicMock()
                proc.cpu_percent.return_value = 45.0
                mock_psutil.Process.return_value = proc

                events = detector.check()

        assert events == []

    def test_no_process_no_hang(self, config: MonitorConfig) -> None:
        """If Autopsy isn't running, no hang to report."""
        detector = HangDetector(config)

        with patch.object(HangDetector, "_find_autopsy_pid", return_value=None):
            events = detector.check()

        assert events == []


class TestLogStalenessDetection:
    """Crash type 4 (alternate signal): log files stop updating."""

    def test_stale_logs_trigger_hang(self, config: MonitorConfig) -> None:
        """Logs unchanged beyond threshold should fire a WARNING."""
        config.log_stale_timeout = 0.0  # immediate for testing

        log_file = config.case_dir / "Log" / "autopsy.log.0"
        log_file.write_text("some log content", encoding="utf-8")

        detector = HangDetector(config)

        with patch.object(HangDetector, "_find_autopsy_pid", return_value=None):
            with patch.object(HangDetector, "_get_monitored_logs", return_value=[log_file]):
                detector.check()  # first check — records mtime
                events = detector.check()  # second check — log hasn't changed

        hang_events = [e for e in events if e.crash_type == CrashType.HANG]
        assert len(hang_events) == 1
        assert "log activity" in hang_events[0].message.lower()

    def test_fresh_logs_no_hang(self, config: MonitorConfig) -> None:
        """Logs that keep updating should not trigger a hang."""
        log_file = config.case_dir / "Log" / "autopsy.log.0"
        log_file.write_text("line 1\n", encoding="utf-8")

        detector = HangDetector(config)

        with patch.object(HangDetector, "_find_autopsy_pid", return_value=None):
            with patch.object(HangDetector, "_get_monitored_logs", return_value=[log_file]):
                detector.check()  # init

                # Update the log (change mtime)
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write("line 2\n")

                events = detector.check()

        assert events == []
