"""Tests for HangDetector."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.hang_detector import HangDetector
from autopsyguard.models import CrashType, Severity


def _mock_log_detector(ingest_running: bool = True):
    """Create a mock LogDetector with configurable ingest_running state."""
    mock = MagicMock()
    mock.ingest_running = ingest_running
    return mock


class TestHangDetection:
    """Crash type 4: correlated signals detect a hang."""

    def test_multiple_signals_trigger_hang(self, config: MonitorConfig) -> None:
        """Hang requires at least 2 of 3 signals to trigger."""
        config.hang_timeout = 0.0  # immediate for testing
        config.log_stale_timeout = 0.0

        detector = HangDetector(config, log_detector=_mock_log_detector(ingest_running=True))

        log_file = config.case_dir / "Log" / "autopsy.log.0"
        log_file.write_text("some log content", encoding="utf-8")

        # Mock the internal signal methods to simulate 2 active signals
        with patch.object(detector, "_check_cpu_signal") as mock_cpu:
            with patch.object(detector, "_check_log_signal") as mock_log:
                with patch.object(detector, "_check_solr_signal") as mock_solr:
                    # Two signals active
                    mock_cpu.return_value = {"pid": 1000, "cpu": 0.0, "duration": 400}
                    mock_log.return_value = {"stale_seconds": 700, "last_mtime": time.time() - 1000}
                    mock_solr.return_value = None  # Only 2 of 3 needed
                    
                    # First call starts hang tracking
                    detector.check()
                    # Simulate 61 seconds passing for sustained correlation
                    detector._hang_start_time = time.time() - 61
                    events = detector.check()

        hang_events = [e for e in events if e.crash_type == CrashType.HANG]
        assert len(hang_events) == 1
        assert hang_events[0].severity == Severity.CRITICAL
        assert "hang" in hang_events[0].message.lower()

    def test_single_signal_no_hang(self, config: MonitorConfig) -> None:
        """A single signal alone should NOT trigger a hang."""
        config.hang_timeout = 0.0

        detector = HangDetector(config, log_detector=_mock_log_detector(ingest_running=True))

        with patch("autopsyguard.utils.process_utils.find_autopsy_pid", return_value=1000):
            with patch("autopsyguard.detectors.hang_detector.psutil") as mock_psutil:
                proc = MagicMock()
                proc.cpu_percent.return_value = 0.0  # Low CPU signal
                mock_psutil.Process.return_value = proc

                # No stale logs, no Solr issues = only 1 signal
                with patch.object(HangDetector, "_check_log_signal", return_value=None):
                    with patch.object(HangDetector, "_check_solr_signal", return_value=None):
                        events = detector.check()

        # Should NOT trigger with only 1 signal
        assert events == []

    def test_normal_cpu_no_hang(self, config: MonitorConfig) -> None:
        """Active CPU should not contribute to hang detection."""
        detector = HangDetector(config, log_detector=_mock_log_detector(ingest_running=True))

        with patch("autopsyguard.utils.process_utils.find_autopsy_pid", return_value=1000):
            with patch("autopsyguard.detectors.hang_detector.psutil") as mock_psutil:
                proc = MagicMock()
                proc.cpu_percent.return_value = 45.0  # Normal CPU
                mock_psutil.Process.return_value = proc

                events = detector.check()

        assert events == []

    def test_no_process_no_hang(self, config: MonitorConfig) -> None:
        """If Autopsy isn't running, no hang to report."""
        detector = HangDetector(config, log_detector=_mock_log_detector(ingest_running=True))

        with patch("autopsyguard.utils.process_utils.find_autopsy_pid", return_value=None):
            events = detector.check()

        assert events == []

    def test_hang_clears_when_signals_recover(self, config: MonitorConfig) -> None:
        """Hang state should clear when signals recover."""
        detector = HangDetector(config, log_detector=_mock_log_detector(ingest_running=True))
        detector._hang_reported = True
        detector._hang_start_time = time.time() - 100

        # All signals clear
        with patch.object(HangDetector, "_check_cpu_signal", return_value=None):
            with patch.object(HangDetector, "_check_log_signal", return_value=None):
                with patch.object(HangDetector, "_check_solr_signal", return_value=None):
                    detector.check()

        # Hang should be cleared
        assert detector._hang_reported is False
        assert detector._hang_start_time is None

    def test_no_hang_when_ingest_not_running(self, config: MonitorConfig) -> None:
        """If no ingest job is active, hang should NOT trigger.

        This covers the case where Autopsy is open but idle (e.g. the user
        is browsing results without running any ingest modules).
        """
        config.hang_timeout = 0.0
        config.log_stale_timeout = 0.0

        # LogDetector says ingest is NOT running
        detector = HangDetector(config, log_detector=_mock_log_detector(ingest_running=False))

        with patch.object(detector, "_check_cpu_signal") as mock_cpu:
            with patch.object(detector, "_check_log_signal") as mock_log:
                with patch.object(detector, "_check_solr_signal") as mock_solr:
                    mock_cpu.return_value = {"pid": 1000, "cpu": 0.0, "duration": 400}
                    mock_log.return_value = {"stale_seconds": 700, "last_mtime": time.time() - 1000}
                    mock_solr.return_value = None

                    detector._hang_start_time = time.time() - 61
                    events = detector.check()

        # Should NOT trigger because no ingest job is active
        assert events == []
        assert detector._hang_reported is False
