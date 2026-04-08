"""Tests for ProcessDetector."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.process_detector import ProcessDetector
from autopsyguard.models import CrashType, Severity


class TestProcessDisappearance:
    """Crash type 1: main Autopsy process terminates unexpectedly."""

    def test_no_process_no_lock_returns_empty(self, config: MonitorConfig) -> None:
        """When no Autopsy is running and no stale lock, nothing to report."""
        detector = ProcessDetector(config)
        with patch("autopsyguard.detectors.process_detector.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = []
            events = detector.check()
        assert events == []

    def test_stale_lock_file_detected(self, config: MonitorConfig) -> None:
        """A lock file with no running process means a previous crash."""
        lock_file = config.case_dir / "Log" / "autopsy.log.0.lck"
        lock_file.write_text("", encoding="utf-8")

        detector = ProcessDetector(config)
        with patch("autopsyguard.detectors.process_detector.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = []
            events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.PROCESS_DISAPPEARED
        assert "lock file" in events[0].message.lower()

    def test_process_found_then_disappears(self, config: MonitorConfig) -> None:
        """Simulate: process is discovered, then vanishes on next check."""
        import psutil as real_psutil

        detector = ProcessDetector(config)

        # First check: process is alive
        fake_proc = MagicMock()
        fake_proc.info = {"pid": 1234, "name": "autopsy64.exe"}
        with patch("autopsyguard.utils.process_utils.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [fake_proc]
            mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess
            mock_psutil.AccessDenied = real_psutil.AccessDenied
            with patch("autopsyguard.detectors.process_detector.psutil") as mock_psutil_detector:
                mock_psutil_detector.Process.return_value.children.return_value = []
                events = detector.check()
        assert events == []
        assert detector._tracked_pid == 1234

        # Second check: process gone
        with patch("autopsyguard.detectors.process_detector.psutil") as mock_psutil:
            mock_psutil.pid_exists.return_value = False
            mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess
            mock_psutil.TimeoutExpired = real_psutil.TimeoutExpired
            mock_psutil.AccessDenied = real_psutil.AccessDenied
            mock_psutil.Process.side_effect = real_psutil.NoSuchProcess(1234)
            events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.PROCESS_DISAPPEARED
        assert events[0].severity == Severity.CRITICAL
        assert "1234" in events[0].message

    def test_does_not_re_report_same_disappearance(self, config: MonitorConfig) -> None:
        """After reporting disappearance, don't fire again until a new process."""
        import psutil as real_psutil

        detector = ProcessDetector(config)
        detector._tracked_pid = 1234
        detector._process_lost_reported = False

        with patch("autopsyguard.detectors.process_detector.psutil") as mock_psutil:
            mock_psutil.pid_exists.return_value = False
            mock_psutil.NoSuchProcess = real_psutil.NoSuchProcess
            mock_psutil.TimeoutExpired = real_psutil.TimeoutExpired
            mock_psutil.AccessDenied = real_psutil.AccessDenied
            mock_psutil.Process.side_effect = real_psutil.NoSuchProcess(1234)
            events1 = detector.check()

        # After reporting, tracked_pid is reset; next check finds nothing
        with patch("autopsyguard.detectors.process_detector.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = []
            events2 = detector.check()

        assert len(events1) == 1
        assert events2 == []


class TestSolrSubprocessCrash:
    """Crash type 5: child Java process dies while Autopsy lives."""

    def test_child_disappearance_detected(self, config: MonitorConfig) -> None:
        """Simulate a Solr child process dying."""
        detector = ProcessDetector(config)
        detector._tracked_pid = 1000
        detector._tracked_children = {2000, 3000}
        detector._process_lost_reported = False

        # Parent alive, but child 2000 is gone
        with patch("autopsyguard.detectors.process_detector.psutil") as mock_psutil:
            mock_psutil.pid_exists.return_value = True

            parent_proc = MagicMock()
            parent_proc.status.return_value = "running"
            child_3000 = MagicMock()
            child_3000.pid = 3000
            child_3000.name.return_value = "java.exe"
            parent_proc.children.return_value = [child_3000]

            mock_psutil.Process.return_value = parent_proc
            events = detector.check()

        solr_events = [e for e in events if e.crash_type == CrashType.SOLR_CRASH]
        assert len(solr_events) == 1
        assert "2000" in solr_events[0].message


class TestAbnormalExit:
    """Crash type 7: process exits with non-zero code."""

    def test_nonzero_exit_code_reported(self, config: MonitorConfig) -> None:
        """When exit code is available and non-zero, report ABNORMAL_EXIT."""
        detector = ProcessDetector(config)
        detector._tracked_pid = 5000
        detector._process_lost_reported = False

        with patch("autopsyguard.detectors.process_detector.psutil") as mock_psutil:
            mock_psutil.pid_exists.return_value = False

            # _get_exit_code will try psutil.Process(pid).wait(timeout=0)
            zombie = MagicMock()
            zombie.wait.return_value = 1
            mock_psutil.Process.return_value = zombie
            mock_psutil.NoSuchProcess = __import__("psutil").NoSuchProcess
            mock_psutil.TimeoutExpired = __import__("psutil").TimeoutExpired
            mock_psutil.AccessDenied = __import__("psutil").AccessDenied

            events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.ABNORMAL_EXIT
        assert events[0].details["exit_code"] == 1
