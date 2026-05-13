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


class TestExternalMemoryPressure:
    """Detect when other processes (not Autopsy) are consuming system memory."""

    def test_external_pressure_triggers_warning(self, config: MonitorConfig) -> None:
        """When system memory is high but Autopsy uses little, alert with top consumers."""
        config.memory_warning_percent = 85.0

        detector = ResourceDetector(config)

        MemInfo = namedtuple("MemInfo", ["rss"])
        VmemResult = namedtuple("VmemResult", ["percent", "used", "total"])

        with patch("autopsyguard.utils.process_utils.find_autopsy_pid") as mock_find:
            mock_find.return_value = 1000
            with patch("autopsyguard.detectors.resource_detector.psutil") as mock_psutil:
                # Autopsy process: small RSS (2 GB out of 30 GB used)
                proc = MagicMock()
                proc.cpu_percent.return_value = 10.0
                proc.memory_info.return_value = MemInfo(rss=2 * 1024**3)
                mock_psutil.Process.return_value = proc

                # System memory: 93% used (30 GB of 32 GB)
                mock_psutil.virtual_memory.return_value = VmemResult(
                    percent=93.0,
                    used=30 * 1024**3,
                    total=32 * 1024**3,
                )
                mock_psutil.disk_usage.return_value = MagicMock(
                    free=50 * 1024**3, total=100 * 1024**3
                )
                mock_psutil.cpu_count.return_value = 8

                # Mock process_iter to return some "heavy" processes
                fake_procs = []
                for name, pid, rss_gb in [
                    ("TiWorker.exe", 5000, 8),
                    ("MsMpEng.exe", 5001, 5),
                    ("chrome.exe", 5002, 4),
                ]:
                    fp = MagicMock()
                    fp.info = {
                        "pid": pid,
                        "name": name,
                        "memory_info": MagicMock(rss=rss_gb * 1024**3),
                    }
                    fake_procs.append(fp)
                mock_psutil.process_iter.return_value = fake_procs
                mock_psutil.NoSuchProcess = Exception
                mock_psutil.AccessDenied = PermissionError

                events = detector.check()

        ext_events = [e for e in events if "Other processes" in e.message]
        assert len(ext_events) == 1
        assert "TiWorker.exe" in ext_events[0].details["top_consumers"]

    def test_no_warning_when_autopsy_is_main_consumer(self, config: MonitorConfig) -> None:
        """When Autopsy uses most of the memory, no external pressure alert."""
        config.memory_warning_percent = 85.0

        detector = ResourceDetector(config)

        MemInfo = namedtuple("MemInfo", ["rss"])
        VmemResult = namedtuple("VmemResult", ["percent", "used", "total"])

        with patch("autopsyguard.utils.process_utils.find_autopsy_pid") as mock_find:
            mock_find.return_value = 1000
            with patch("autopsyguard.detectors.resource_detector.psutil") as mock_psutil:
                # Autopsy uses 20 GB out of 30 GB used (66% — dominant consumer)
                proc = MagicMock()
                proc.cpu_percent.return_value = 10.0
                proc.memory_info.return_value = MemInfo(rss=20 * 1024**3)
                mock_psutil.Process.return_value = proc

                mock_psutil.virtual_memory.return_value = VmemResult(
                    percent=93.0,
                    used=30 * 1024**3,
                    total=32 * 1024**3,
                )
                mock_psutil.disk_usage.return_value = MagicMock(
                    free=50 * 1024**3, total=100 * 1024**3
                )
                mock_psutil.cpu_count.return_value = 8
                mock_psutil.NoSuchProcess = Exception
                mock_psutil.AccessDenied = PermissionError

                events = detector.check()

        ext_events = [e for e in events if "Other processes" in e.message]
        assert len(ext_events) == 0


