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
import autopsyguard.utils.process_utils as process_utils

logger = logging.getLogger(__name__)


class ResourceDetector(BaseDetector):
    """Monitors CPU, memory, and disk usage for anomalies."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__(config)
        self._high_cpu_since: float | None = None
        self._cpu_warning_reported = False
        self._mem_warning_reported = False
        self._disk_warning_reported = False
        self._external_mem_warning_reported = False
        # Track whether we've seen a cpu_percent sample for a given PID
        # because psutil returns 0.0 on the very first call for a process.
        self._seen_cpu_pid: set[int] = set()

    @property
    def name(self) -> str:
        return "ResourceDetector"

    def check(self) -> list[CrashEvent]:
        events: list[CrashEvent] = []

        pid = process_utils.find_autopsy_pid()
        if pid is not None:
            events.extend(self._check_cpu(pid))
            events.extend(self._check_memory(pid))
            events.extend(self._check_external_memory_pressure(pid))

        events.extend(self._check_disk())

        return events

    # ------------------------------------------------------------------
    # CPU
    # ------------------------------------------------------------------

    def _check_cpu(self, pid: int) -> list[CrashEvent]:
        now = time.time()
        try:
            proc = psutil.Process(pid)
            # Use non-blocking measurement: `interval=None` returns the
            # percentage since the last call to `cpu_percent()` for this
            # process. This avoids blocking the monitoring loop for 100ms
            # per detector call. Note: the first call after process start
            # may return 0.0; discard that first sample to avoid spurious
            # high-CPU detections immediately after process discovery.
            cpu = proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._high_cpu_since = None
            return []

        # Discard the first non-informative sample for this PID. psutil
        # often returns 0.0 on the first call — in that case we ignore
        # the sample. If the first sample is non-zero (e.g. tests/mocks),
        # treat it as valid.
        if pid not in self._seen_cpu_pid:
            self._seen_cpu_pid.add(pid)
            try:
                cpu_val = float(cpu)
            except Exception:
                cpu_val = None
            if cpu_val == 0.0:
                return []
            if cpu_val is not None:
                cpu = cpu_val

        # Interpret psutil's process CPU percent: can exceed 100% when
        # the process uses multiple logical cores (e.g. 250% ~= 2.5 cores).
        # Normalize cpu_count to an int; mocks may return MagicMock so guard.
        try:
            cpu_count_raw = psutil.cpu_count(logical=True)
            cpu_count = int(cpu_count_raw) if cpu_count_raw else 1
        except Exception:
            cpu_count = 1

        # Ensure numeric cpu value
        try:
            cpu = float(cpu)
        except Exception:
            cpu = 0.0

        cores_used = cpu / 100.0
        per_core_percent = (cpu / cpu_count) if cpu_count else cpu

        # Trigger if either total process CPU percentage exceeds the configured
        # process-wide threshold OR the per-core average exceeds the per-core threshold.
        # Compare using floats and guard against non-numeric values from mocks
        try:
            triggers_total = float(cpu) >= float(self.config.cpu_warning_percent)
        except Exception:
            triggers_total = False
        try:
            triggers_per_core = float(per_core_percent) >= float(getattr(self.config, "cpu_per_core_warning_percent", 100.0))
        except Exception:
            triggers_per_core = False

        if triggers_total or triggers_per_core:
            if self._high_cpu_since is None:
                self._high_cpu_since = now
            elapsed = now - self._high_cpu_since
            if elapsed >= self.config.cpu_warning_duration and not self._cpu_warning_reported:
                self._cpu_warning_reported = True
                # Build a clearer message including cores used and per-core percent
                message_parts = [
                    f"Autopsy (PID {pid}) sustained CPU at {cpu:.1f}%",
                    f"(≈{cores_used:.1f} cores; ≈{per_core_percent:.1f}% per core)",
                ]
                if triggers_total and not triggers_per_core:
                    message_parts.append(f"exceeding total threshold {self.config.cpu_warning_percent:.0f}%")
                elif triggers_per_core and not triggers_total:
                    message_parts.append(f"exceeding per-core threshold {self.config.cpu_per_core_warning_percent:.0f}%")
                else:
                    message_parts.append("exceeding both total and per-core thresholds")
                message_parts.append(f"for {elapsed:.0f}s")
                message = " ".join(message_parts)
                return [CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.WARNING,
                    message=message,
                    details={
                        "pid": pid,
                        "cpu_percent": cpu,
                        "cores_used": cores_used,
                        "cpu_count": cpu_count,
                        "cpu_per_core_percent": per_core_percent,
                        "cpu_per_core_warning_percent": getattr(self.config, "cpu_per_core_warning_percent", None),
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

        try:
            rss = int(mem_info.rss)
            total = int(system_mem.total)
            usage_percent = (rss / total) * 100
        except Exception:
            # Be defensive in tests where memory fields may be mocked
            return []

        if usage_percent >= self.config.memory_warning_percent:
            if not self._mem_warning_reported:
                self._mem_warning_reported = True
                rss_gb = rss / (1024**3)
                total_bytes = int(system_mem.total)
                return [CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.WARNING,
                    message=(
                        f"Autopsy (PID {pid}) using {usage_percent:.1f}% "
                        f"of system RAM ({rss_gb:.1f} GB)"
                    ),
                    details={
                        "pid": pid,
                        "rss_bytes": rss,
                        "system_total_bytes": total_bytes,
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
    # External memory pressure
    # ------------------------------------------------------------------

    def _check_external_memory_pressure(self, pid: int) -> list[CrashEvent]:
        """Detect when system memory is high but Autopsy is NOT the main consumer.

        If total system memory usage exceeds the warning threshold but Autopsy
        accounts for less than half of the used memory, another process is the
        real cause.  Report the top memory consumers so the user can act.
        """
        try:
            system_mem = psutil.virtual_memory()
            proc = psutil.Process(pid)
            autopsy_rss = proc.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

        try:
            system_used = int(system_mem.used)
            system_total = int(system_mem.total)
            system_percent = float(system_mem.percent)
            autopsy_rss = int(autopsy_rss)
        except Exception:
            return []

        # Only trigger when system memory is high
        if system_percent < self.config.memory_warning_percent:
            self._external_mem_warning_reported = False
            return []

        # Check if Autopsy is NOT the main consumer (< 50% of used memory)
        autopsy_fraction = autopsy_rss / system_used if system_used > 0 else 1.0
        if autopsy_fraction >= 0.5:
            # Autopsy is the dominant consumer — the existing memory check handles this
            self._external_mem_warning_reported = False
            return []

        if self._external_mem_warning_reported:
            return []

        # Find top 5 non-Autopsy processes by memory
        from autopsyguard.platform_utils import get_autopsy_process_names, get_java_process_names
        autopsy_names = {n.lower() for n in get_autopsy_process_names()}
        java_names = {n.lower() for n in get_java_process_names()}
        exclude_pids = {pid}  # Autopsy PID

        top_procs: list[tuple[str, int, float]] = []  # (name, pid, rss_bytes)
        try:
            for p in psutil.process_iter(["pid", "name", "memory_info"]):
                try:
                    p_pid = p.info["pid"]
                    p_name = (p.info.get("name") or "").lower()
                    p_mem = p.info.get("memory_info")
                    if p_pid in exclude_pids or p_name in autopsy_names:
                        continue
                    if p_mem is not None:
                        rss = int(p_mem.rss)
                        top_procs.append((p.info.get("name") or "unknown", p_pid, rss))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            return []

        # Sort by RSS descending and take top 5
        top_procs.sort(key=lambda x: x[2], reverse=True)
        top_5 = top_procs[:5]

        # Build message
        autopsy_gb = autopsy_rss / (1024**3)
        other_used_gb = (system_used - autopsy_rss) / (1024**3)
        top_list = ", ".join(
            f"{name} (PID {p_pid}, {rss / (1024**3):.1f} GB)"
            for name, p_pid, rss in top_5
        )

        self._external_mem_warning_reported = True
        return [CrashEvent(
            crash_type=CrashType.HIGH_RESOURCE_USAGE,
            severity=Severity.WARNING,
            message=(
                f"System memory at {system_percent:.1f}% but Autopsy only uses "
                f"{autopsy_gb:.1f} GB ({autopsy_fraction * 100:.0f}% of used). "
                f"Other processes are consuming {other_used_gb:.1f} GB."
            ),
            details={
                "system_memory_percent": system_percent,
                "autopsy_rss_gb": round(autopsy_gb, 2),
                "autopsy_fraction_of_used": round(autopsy_fraction * 100, 1),
                "other_used_gb": round(other_used_gb, 2),
                "top_consumers": top_list,
            },
        )]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

