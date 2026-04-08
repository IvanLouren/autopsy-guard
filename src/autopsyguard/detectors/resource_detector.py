"""Detect abnormal resource consumption by the Autopsy process.

Covers crash type 6: High Resource Consumption (CPU, memory, disk).

This is an anomaly detector — it fires warnings when Autopsy's resource
usage exceeds configured thresholds, which often precedes a crash.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import psutil

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.utils.process_utils import find_autopsy_pid

logger = logging.getLogger(__name__)


class ResourceDetector(BaseDetector):
    """Monitors CPU, memory, and disk usage for anomalies."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__(config)
        self._high_cpu_since: float | None = None
        self._cpu_warning_reported = False
        self._mem_warning_reported = False
        self._disk_warning_reported = False

    @property
    def name(self) -> str:
        return "ResourceDetector"

    def check(self) -> list[CrashEvent]:
        events: list[CrashEvent] = []

        pid = find_autopsy_pid()
        if pid is not None:
            events.extend(self._check_cpu(pid))
            events.extend(self._check_memory(pid))

        events.extend(self._check_disk())

        return events

    # ------------------------------------------------------------------
    # CPU
    # ------------------------------------------------------------------

    def _check_cpu(self, pid: int) -> list[CrashEvent]:
        now = time.time()
        try:
            proc = psutil.Process(pid)
            cpu = proc.cpu_percent(interval=0.1)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._high_cpu_since = None
            return []

        if cpu >= self.config.cpu_warning_percent:
            if self._high_cpu_since is None:
                self._high_cpu_since = now
            elapsed = now - self._high_cpu_since
            if elapsed >= self.config.cpu_warning_duration and not self._cpu_warning_reported:
                self._cpu_warning_reported = True
                return [CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.WARNING,
                    message=(
                        f"Autopsy (PID {pid}) sustained CPU at {cpu:.1f}% "
                        f"for {elapsed:.0f}s"
                    ),
                    details={
                        "pid": pid,
                        "cpu_percent": cpu,
                        "duration_seconds": elapsed,
                    },
                )]
        else:
            self._high_cpu_since = None
            self._cpu_warning_reported = False

        return []

    # ------------------------------------------------------------------
    # Memory
    # ------------------------------------------------------------------

    def _check_memory(self, pid: int) -> list[CrashEvent]:
        try:
            proc = psutil.Process(pid)
            mem_info = proc.memory_info()
            system_mem = psutil.virtual_memory()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

        usage_percent = (mem_info.rss / system_mem.total) * 100

        if usage_percent >= self.config.memory_warning_percent:
            if not self._mem_warning_reported:
                self._mem_warning_reported = True
                return [CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.WARNING,
                    message=(
                        f"Autopsy (PID {pid}) using {usage_percent:.1f}% "
                        f"of system RAM ({mem_info.rss / (1024**3):.1f} GB)"
                    ),
                    details={
                        "pid": pid,
                        "rss_bytes": mem_info.rss,
                        "system_total_bytes": system_mem.total,
                        "usage_percent": usage_percent,
                    },
                )]
        else:
            self._mem_warning_reported = False

        return []

    # ------------------------------------------------------------------
    # Disk
    # ------------------------------------------------------------------

    def _check_disk(self) -> list[CrashEvent]:
        """Check free space on the partition hosting the case directory."""
        case_dir = self.config.case_dir
        if not case_dir.is_dir():
            return []

        try:
            usage = psutil.disk_usage(str(case_dir))
        except OSError:
            return []

        free_gb = usage.free / (1024**3)

        if free_gb < self.config.disk_min_free_gb:
            if not self._disk_warning_reported:
                self._disk_warning_reported = True
                return [CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.CRITICAL,
                    message=(
                        f"Disk space critically low: {free_gb:.2f} GB free "
                        f"on {case_dir.anchor}"
                    ),
                    details={
                        "free_gb": free_gb,
                        "total_gb": usage.total / (1024**3),
                        "partition": case_dir.anchor,
                    },
                )]
        else:
            self._disk_warning_reported = False

        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

