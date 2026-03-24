"""Tests for JvmCrashDetector."""

from __future__ import annotations

from pathlib import Path

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.jvm_crash_detector import JvmCrashDetector
from autopsyguard.models import CrashType, Severity


class TestJvmCrashDetector:
    """Crash type 2: JVM fatal crash producing hs_err_pid*.log."""

    def test_initial_scan_does_not_alert(self, config: MonitorConfig, tmp_path: Path) -> None:
        """Pre-existing hs_err files should be recorded but not reported."""
        config.autopsy_install_dir = tmp_path
        # Create a pre-existing crash file
        (tmp_path / "hs_err_pid1234.log").write_text("# old crash", encoding="utf-8")

        detector = JvmCrashDetector(config)
        events = detector.check()

        assert events == []
        assert detector._initialised

    def test_new_crash_file_triggers_event(self, config: MonitorConfig, tmp_path: Path) -> None:
        """A new hs_err file appearing after init should fire a CRITICAL event."""
        config.autopsy_install_dir = tmp_path

        detector = JvmCrashDetector(config)
        detector.check()  # initialise

        # Simulate a JVM crash: new file appears
        crash_file = tmp_path / "hs_err_pid9999.log"
        crash_file.write_text(
            "# A fatal error has been detected by the Java Runtime Environment:\n"
            "#\n"
            "#  SIGSEGV (0xb) at pc=0x00007f..., pid=9999, tid=1\n"
            "#\n"
            "# JRE version: OpenJDK 17.0.7\n",
            encoding="utf-8",
        )

        events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.JVM_CRASH
        assert events[0].severity == Severity.CRITICAL
        assert "9999" in events[0].message
        assert "SIGSEGV" in events[0].details["summary"]

    def test_same_file_not_reported_twice(self, config: MonitorConfig, tmp_path: Path) -> None:
        """Once reported, the same hs_err file should not trigger again."""
        config.autopsy_install_dir = tmp_path

        detector = JvmCrashDetector(config)
        detector.check()  # init

        (tmp_path / "hs_err_pid5555.log").write_text("# crash", encoding="utf-8")
        events1 = detector.check()
        events2 = detector.check()

        assert len(events1) == 1
        assert events2 == []

    def test_multiple_new_files(self, config: MonitorConfig, tmp_path: Path) -> None:
        """Multiple new crash files should each produce an event."""
        config.autopsy_install_dir = tmp_path

        detector = JvmCrashDetector(config)
        detector.check()  # init

        (tmp_path / "hs_err_pid1111.log").write_text("# crash 1", encoding="utf-8")
        (tmp_path / "hs_err_pid2222.log").write_text("# crash 2", encoding="utf-8")

        events = detector.check()

        assert len(events) == 2
        pids_in_messages = {e.details["file"] for e in events}
        assert any("1111" in p for p in pids_in_messages)
        assert any("2222" in p for p in pids_in_messages)

    def test_no_crash_dir_does_not_fail(self, config: MonitorConfig) -> None:
        """If the install dir doesn't exist, detector handles it gracefully."""
        config.autopsy_install_dir = Path("C:/nonexistent/path")

        detector = JvmCrashDetector(config)
        events = detector.check()  # init
        events = detector.check()  # regular check

        assert events == []
