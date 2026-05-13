"""Tests for Autopsy per-process disk I/O tracking.

Covers:
- MetricsStore schema migration v3 (autopsy_read_bytes / autopsy_write_bytes)
- record_sample() captures per-process I/O via psutil.Process.io_counters()
- Chart rendering with Autopsy I/O data (dashed lines on bottom panel)
"""

from __future__ import annotations

import sqlite3
from collections import namedtuple
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from autopsyguard.utils.metrics_store import MetricsStore
from autopsyguard.utils.metrics_chart import render_system_chart_png


class TestMetricsStoreIO:
    """Verify that per-process Autopsy I/O is stored in the DB."""

    def test_migration_v3_adds_autopsy_io_columns(self, tmp_path: Path) -> None:
        """Schema migration v3 should add autopsy_read_bytes and autopsy_write_bytes."""
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        db_path = tmp_path / "test.db"

        store = MetricsStore(case_dir=case_dir, db_path=db_path)

        # Check the columns exist
        cols = store._get_table_columns("metrics")
        assert "autopsy_read_bytes" in cols
        assert "autopsy_write_bytes" in cols
        store.close()

    def test_record_sample_captures_autopsy_io(self, tmp_path: Path) -> None:
        """record_sample() should store Autopsy read/write bytes when process is found."""
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        db_path = tmp_path / "test.db"

        store = MetricsStore(case_dir=case_dir, db_path=db_path)

        # Mock all psutil calls
        IoCounters = namedtuple("IoCounters", ["read_count", "write_count", "read_bytes", "write_bytes"])
        MemInfo = namedtuple("MemInfo", ["rss"])
        VirtualMem = namedtuple("VirtualMem", ["percent", "used", "total"])
        DiskUsage = namedtuple("DiskUsage", ["free", "total"])
        DiskIO = namedtuple("DiskIO", ["read_bytes", "write_bytes", "read_count", "write_count", "read_time", "write_time"])

        mock_proc = MagicMock()
        mock_proc.memory_info.return_value = MemInfo(rss=2 * 1024**3)
        mock_proc.io_counters.return_value = IoCounters(
            read_count=100, write_count=50,
            read_bytes=500_000_000,  # 500 MB read
            write_bytes=200_000_000,  # 200 MB written
        )

        with patch("autopsyguard.utils.metrics_store.find_autopsy_pid", return_value=1234), \
             patch("autopsyguard.utils.metrics_store.psutil") as mock_psutil:
            mock_psutil.cpu_percent.return_value = 45.0
            mock_psutil.virtual_memory.return_value = VirtualMem(percent=60.0, used=8*1024**3, total=16*1024**3)
            mock_psutil.disk_usage.return_value = DiskUsage(free=100*1024**3, total=500*1024**3)
            mock_psutil.disk_io_counters.return_value = DiskIO(
                read_bytes=1_000_000_000, write_bytes=800_000_000,
                read_count=5000, write_count=3000, read_time=100, write_time=80,
            )
            mock_psutil.Process.return_value = mock_proc
            mock_psutil.NoSuchProcess = Exception
            mock_psutil.AccessDenied = PermissionError

            store.record_sample()

        # Fetch and verify
        samples = store.fetch_samples(since_ts=0)
        assert len(samples) == 1
        sample = samples[0]
        assert sample["autopsy_read_bytes"] == 500_000_000
        assert sample["autopsy_write_bytes"] == 200_000_000
        store.close()

    def test_record_sample_no_autopsy_process(self, tmp_path: Path) -> None:
        """When Autopsy is not running, autopsy I/O should be 0."""
        case_dir = tmp_path / "case"
        case_dir.mkdir()
        db_path = tmp_path / "test.db"

        store = MetricsStore(case_dir=case_dir, db_path=db_path)

        VirtualMem = namedtuple("VirtualMem", ["percent", "used", "total"])
        DiskUsage = namedtuple("DiskUsage", ["free", "total"])
        DiskIO = namedtuple("DiskIO", ["read_bytes", "write_bytes", "read_count", "write_count", "read_time", "write_time"])

        with patch("autopsyguard.utils.metrics_store.find_autopsy_pid", return_value=None), \
             patch("autopsyguard.utils.metrics_store.psutil") as mock_psutil:
            mock_psutil.cpu_percent.return_value = 10.0
            mock_psutil.virtual_memory.return_value = VirtualMem(percent=40.0, used=4*1024**3, total=16*1024**3)
            mock_psutil.disk_usage.return_value = DiskUsage(free=200*1024**3, total=500*1024**3)
            mock_psutil.disk_io_counters.return_value = DiskIO(
                read_bytes=100_000, write_bytes=50_000,
                read_count=10, write_count=5, read_time=1, write_time=1,
            )

            store.record_sample()

        samples = store.fetch_samples(since_ts=0)
        assert len(samples) == 1
        assert samples[0]["autopsy_read_bytes"] == 0
        assert samples[0]["autopsy_write_bytes"] == 0
        store.close()


class TestChartWithAutopsyIO:
    """Verify that the chart renders Autopsy I/O lines when data is present."""

    def test_chart_renders_with_autopsy_io(self) -> None:
        """Chart should render successfully when autopsy I/O data is present."""
        import time
        t0 = time.time()
        samples = [
            {
                "ts": t0,
                "cpu_percent": 50.0, "memory_percent": 60.0,
                "disk_read_bytes": 0, "disk_write_bytes": 0,
                "autopsy_rss_bytes": 2 * 1024**3,
                "autopsy_read_bytes": 0, "autopsy_write_bytes": 0,
            },
            {
                "ts": t0 + 10,
                "cpu_percent": 55.0, "memory_percent": 62.0,
                "disk_read_bytes": 100_000_000, "disk_write_bytes": 50_000_000,
                "autopsy_rss_bytes": 2.1 * 1024**3,
                "autopsy_read_bytes": 80_000_000, "autopsy_write_bytes": 30_000_000,
            },
            {
                "ts": t0 + 20,
                "cpu_percent": 60.0, "memory_percent": 65.0,
                "disk_read_bytes": 250_000_000, "disk_write_bytes": 120_000_000,
                "autopsy_rss_bytes": 2.2 * 1024**3,
                "autopsy_read_bytes": 200_000_000, "autopsy_write_bytes": 90_000_000,
            },
        ]

        png_bytes = render_system_chart_png(samples)

        # Should return valid PNG data (starts with PNG magic bytes)
        assert len(png_bytes) > 0
        assert png_bytes[:4] == b"\x89PNG"

    def test_chart_renders_without_autopsy_io(self) -> None:
        """Chart should still render when autopsy I/O data is absent (old DB schema)."""
        import time
        t0 = time.time()
        samples = [
            {
                "ts": t0,
                "cpu_percent": 50.0, "memory_percent": 60.0,
                "disk_read_bytes": 0, "disk_write_bytes": 0,
                "autopsy_rss_bytes": None,
                # No autopsy_read_bytes / autopsy_write_bytes keys
            },
            {
                "ts": t0 + 10,
                "cpu_percent": 55.0, "memory_percent": 62.0,
                "disk_read_bytes": 100_000_000, "disk_write_bytes": 50_000_000,
                "autopsy_rss_bytes": None,
            },
        ]

        png_bytes = render_system_chart_png(samples)

        assert len(png_bytes) > 0
        assert png_bytes[:4] == b"\x89PNG"
