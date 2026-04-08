"""Tests for ResourceDetector."""

from __future__ import annotations

from collections import namedtuple
from unittest.mock import MagicMock, patch

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.resource_detector import ResourceDetector
from autopsyguard.models import CrashType, Severity


class TestCpuMonitoring:
    """Crash type 6: sustained high CPU."""

    def test_high_cpu_triggers_warning(self, config: MonitorConfig) -> None:
        config.cpu_warning_duration = 0.0  # immediate for testing
        config.cpu_warning_percent = 95.0

        detector = ResourceDetector(config)

        with patch("autopsyguard.utils.process_utils.find_autopsy_pid") as mock_find:
            mock_find.return_value = 1000
            with patch("autopsyguard.detectors.resource_detector.psutil") as mock_psutil:
                proc = MagicMock()
                proc.cpu_percent.return_value = 99.0
                MemInfo = namedtuple("MemInfo", ["rss"])
                proc.memory_info.return_value = MemInfo(rss=1 * 1024**3)
                mock_psutil.Process.return_value = proc

                VmemResult = namedtuple("VmemResult", ["total"])
                mock_psutil.virtual_memory.return_value = VmemResult(total=16 * 1024**3)
                mock_psutil.disk_usage.return_value = MagicMock(
                    free=50 * 1024**3, total=100 * 1024**3
                )

                events = detector.check()

        resource_events = [e for e in events if e.crash_type == CrashType.HIGH_RESOURCE_USAGE]
        assert len(resource_events) >= 1
        assert any("CPU" in e.message for e in resource_events)

    def test_normal_cpu_no_warning(self, config: MonitorConfig) -> None:
        detector = ResourceDetector(config)

        with patch("autopsyguard.utils.process_utils.find_autopsy_pid") as mock_find:
            mock_find.return_value = 1000
            with patch("autopsyguard.detectors.resource_detector.psutil") as mock_psutil:
                proc = MagicMock()
                proc.cpu_percent.return_value = 50.0
                MemInfo = namedtuple("MemInfo", ["rss"])
                proc.memory_info.return_value = MemInfo(rss=1 * 1024**3)
                mock_psutil.Process.return_value = proc

                VmemResult = namedtuple("VmemResult", ["total"])
                mock_psutil.virtual_memory.return_value = VmemResult(total=16 * 1024**3)
                mock_psutil.disk_usage.return_value = MagicMock(
                    free=50 * 1024**3, total=100 * 1024**3
                )

                events = detector.check()

        assert events == []


class TestMemoryMonitoring:
    """Crash type 6: excessive memory usage."""

    def test_high_memory_triggers_warning(self, config: MonitorConfig) -> None:
        config.memory_warning_percent = 90.0

        detector = ResourceDetector(config)

        with patch("autopsyguard.utils.process_utils.find_autopsy_pid") as mock_find:
            mock_find.return_value = 1000
            with patch("autopsyguard.detectors.resource_detector.psutil") as mock_psutil:
                proc = MagicMock()
                proc.cpu_percent.return_value = 10.0
                MemInfo = namedtuple("MemInfo", ["rss"])
                proc.memory_info.return_value = MemInfo(rss=15 * 1024**3)
                mock_psutil.Process.return_value = proc

                VmemResult = namedtuple("VmemResult", ["total"])
                mock_psutil.virtual_memory.return_value = VmemResult(total=16 * 1024**3)
                mock_psutil.disk_usage.return_value = MagicMock(
                    free=50 * 1024**3, total=100 * 1024**3
                )

                events = detector.check()

        mem_events = [e for e in events if "RAM" in e.message]
        assert len(mem_events) == 1
        assert mem_events[0].severity == Severity.WARNING


class TestDiskMonitoring:
    """Crash type 6: disk space exhaustion."""

    def test_low_disk_triggers_critical(self, config: MonitorConfig) -> None:
        config.disk_min_free_gb = 5.0

        detector = ResourceDetector(config)

        with patch("autopsyguard.utils.process_utils.find_autopsy_pid") as mock_find:
            mock_find.return_value = None
            with patch("autopsyguard.detectors.resource_detector.psutil") as mock_psutil:
                DiskUsage = namedtuple("DiskUsage", ["free", "total"])
                mock_psutil.disk_usage.return_value = DiskUsage(
                    free=int(0.5 * 1024**3),
                    total=int(500 * 1024**3),
                )

                events = detector.check()

        assert len(events) == 1
        assert events[0].severity == Severity.CRITICAL
        assert "disk" in events[0].message.lower()

    def test_sufficient_disk_no_warning(self, config: MonitorConfig) -> None:
        config.disk_min_free_gb = 1.0

        detector = ResourceDetector(config)

        with patch("autopsyguard.utils.process_utils.find_autopsy_pid") as mock_find:
            mock_find.return_value = None
            with patch("autopsyguard.detectors.resource_detector.psutil") as mock_psutil:
                DiskUsage = namedtuple("DiskUsage", ["free", "total"])
                mock_psutil.disk_usage.return_value = DiskUsage(
                    free=int(100 * 1024**3),
                    total=int(500 * 1024**3),
                )

                events = detector.check()

        assert events == []





