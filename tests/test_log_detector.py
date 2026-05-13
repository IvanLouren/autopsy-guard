"""Tests for LogDetector."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.log_detector import LogDetector
from autopsyguard.models import CrashType, Severity


class TestOutOfMemoryDetection:
    """Crash type 3: OutOfMemoryError in log files."""

    def test_oom_detected_in_case_log(self, config: MonitorConfig) -> None:
        """OOM error appearing in the case log triggers a CRITICAL event."""
        log_file = config.case_dir / "Log" / "autopsy.log.0"
        log_file.write_text("INFO: starting ingest\n", encoding="utf-8")

        detector = LogDetector(config)
        # Patch out global log dir so we only test case log
        with patch.object(LogDetector, "_get_log_files", return_value=[log_file]):
            detector.check()  # init — seek to end

            # Append OOM to log
            with open(log_file, "a", encoding="utf-8") as f:
                f.write("SEVERE: java.lang.OutOfMemoryError: Java heap space\n")

            events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.OUT_OF_MEMORY
        assert events[0].severity == Severity.CRITICAL
        assert "OutOfMemoryError" in events[0].message

    def test_oom_not_reported_from_old_content(self, config: MonitorConfig) -> None:
        """OOM errors already present before monitoring starts are ignored."""
        log_file = config.case_dir / "Log" / "autopsy.log.0"
        log_file.write_text(
            "SEVERE: java.lang.OutOfMemoryError: Java heap space\n",
            encoding="utf-8",
        )

        detector = LogDetector(config)
        with patch.object(LogDetector, "_get_log_files", return_value=[log_file]):
            events = detector.check()  # init

        assert events == []


class TestLogErrorDetection:
    """Crash type 8: SEVERE, exceptions, and FATAL in logs."""

    def test_severe_detected(self, config: MonitorConfig) -> None:
        log_file = config.case_dir / "Log" / "autopsy.log.0"
        log_file.write_text("", encoding="utf-8")

        detector = LogDetector(config)
        with patch.object(LogDetector, "_get_log_files", return_value=[log_file]):
            detector.check()  # init

            with open(log_file, "a", encoding="utf-8") as f:
                f.write("SEVERE: Failed to process file /evidence/disk.E01\n")

            events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.LOG_ERROR
        assert events[0].severity == Severity.WARNING

    def test_fatal_detected_as_critical(self, config: MonitorConfig) -> None:
        log_file = config.case_dir / "Log" / "autopsy.log.0"
        log_file.write_text("", encoding="utf-8")

        detector = LogDetector(config)
        with patch.object(LogDetector, "_get_log_files", return_value=[log_file]):
            detector.check()  # init

            with open(log_file, "a", encoding="utf-8") as f:
                f.write("FATAL: Unrecoverable database corruption\n")

            events = detector.check()

        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL

    def test_exception_detected(self, config: MonitorConfig) -> None:
        log_file = config.case_dir / "Log" / "autopsy.log.0"
        log_file.write_text("", encoding="utf-8")

        detector = LogDetector(config)
        with patch.object(LogDetector, "_get_log_files", return_value=[log_file]):
            detector.check()  # init

            with open(log_file, "a", encoding="utf-8") as f:
                f.write("java.io.IOException: Disk read error\n")

            events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.LOG_ERROR

    def test_log_rotation_handled(self, config: MonitorConfig) -> None:
        """When a log file is rotated (gets smaller), re-read from start."""
        log_file = config.case_dir / "Log" / "autopsy.log.0"
        log_file.write_text("x" * 1000, encoding="utf-8")

        detector = LogDetector(config)
        with patch.object(LogDetector, "_get_log_files", return_value=[log_file]):
            detector.check()  # init, offset = 1000

            # Simulate rotation: file is now small again
            log_file.write_text(
                "SEVERE: error after rotation\n", encoding="utf-8"
            )

            events = detector.check()

        assert len(events) == 1

    def test_normal_info_lines_ignored(self, config: MonitorConfig) -> None:
        """Normal log lines should not produce events."""
        log_file = config.case_dir / "Log" / "autopsy.log.0"
        log_file.write_text("", encoding="utf-8")

        detector = LogDetector(config)
        with patch.object(LogDetector, "_get_log_files", return_value=[log_file]):
            detector.check()  # init

            with open(log_file, "a", encoding="utf-8") as f:
                f.write("INFO: Ingest job started\n")
                f.write("INFO: Processing file evidence.E01\n")
                f.write("INFO: Module RecentActivity completed\n")

            events = detector.check()

        assert events == []
