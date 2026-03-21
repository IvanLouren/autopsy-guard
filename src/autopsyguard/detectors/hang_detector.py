"""Detect Autopsy application hangs/freezes.

Covers crash type 4: Application Hang/Freeze.

A hang is detected via two independent signals:
  - CPU usage near zero for an extended period while the process is alive
  - Log files stop being written to for an extended period
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import psutil

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.platform_utils import get_autopsy_log_dir, get_case_log_file

logger = logging.getLogger(__name__)


class HangDetector(BaseDetector):
    """Detects application hangs via CPU inactivity and log file staleness."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__(config)
        self._low_cpu_since: float | None = None
        self._log_stale_since: float | None = None
        self._last_log_mtime: float | None = None
        self._hang_reported = False

    @property
    def name(self) -> str:
        return "HangDetector"

    def check(self) -> list[CrashEvent]:
        events: list[CrashEvent] = []
        now = time.time()

        cpu_hang = self._check_cpu_hang(now)
        log_hang = self._check_log_stale(now)

        if cpu_hang and not self._hang_reported:
            events.append(cpu_hang)
            self._hang_reported = True
        if log_hang and not self._hang_reported:
            events.append(log_hang)
            self._hang_reported = True

        # Reset if conditions clear
        if not cpu_hang and not log_hang:
            self._hang_reported = False

        return events

    # ------------------------------------------------------------------
    # CPU-based hang detection
    # ------------------------------------------------------------------

    def _check_cpu_hang(self, now: float) -> CrashEvent | None:
        """Detect when Autopsy's CPU usage stays near zero."""
        pid = self._find_autopsy_pid()
        if pid is None:
            self._low_cpu_since = None
            return None

        try:
            proc = psutil.Process(pid)
            cpu = proc.cpu_percent(interval=0)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._low_cpu_since = None
            return None

        if cpu <= self.config.hang_cpu_threshold:
            if self._low_cpu_since is None:
                self._low_cpu_since = now
            elapsed = now - self._low_cpu_since
            if elapsed >= self.config.hang_timeout:
                return CrashEvent(
                    crash_type=CrashType.HANG,
                    severity=Severity.WARNING,
                    message=(
                        f"Autopsy (PID {pid}) CPU at {cpu:.1f}% "
                        f"for {elapsed:.0f}s — possible hang"
                    ),
                    details={
                        "pid": pid,
                        "cpu_percent": cpu,
                        "duration_seconds": elapsed,
                    },
                )
        else:
            self._low_cpu_since = None

        return None

    # ------------------------------------------------------------------
    # Log-staleness-based hang detection
    # ------------------------------------------------------------------

    def _check_log_stale(self, now: float) -> CrashEvent | None:
        """Detect when log files stop being updated."""
        log_files = self._get_monitored_logs()
        if not log_files:
            return None

        latest_mtime = max(
            (f.stat().st_mtime for f in log_files if f.is_file()),
            default=None,
        )
        if latest_mtime is None:
            return None

        if self._last_log_mtime is None:
            self._last_log_mtime = latest_mtime
            return None

        if latest_mtime > self._last_log_mtime:
            # Logs are still being written
            self._last_log_mtime = latest_mtime
            self._log_stale_since = None
            return None

        # Logs haven't changed
        if self._log_stale_since is None:
            self._log_stale_since = now

        stale_duration = now - self._log_stale_since
        if stale_duration >= self.config.log_stale_timeout:
            return CrashEvent(
                crash_type=CrashType.HANG,
                severity=Severity.WARNING,
                message=(
                    f"No log activity for {stale_duration:.0f}s — possible hang"
                ),
                details={
                    "stale_seconds": stale_duration,
                    "log_files": [str(f) for f in log_files],
                },
            )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_monitored_logs(self) -> list[Path]:
        """Collect log files to check for freshness."""
        files: list[Path] = []
        case_log = get_case_log_file(self.config.case_dir)
        if case_log.is_file():
            files.append(case_log)
        global_dir = get_autopsy_log_dir()
        for name in ("messages.log", "autopsy.log.0"):
            p = global_dir / name
            if p.is_file():
                files.append(p)
        return files

    @staticmethod
    def _find_autopsy_pid() -> int | None:
        """Quick scan for the Autopsy process (reuses platform logic)."""
        from autopsyguard.platform_utils import get_autopsy_process_names

        target_names = [n.lower() for n in get_autopsy_process_names()]
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                if proc.info["name"] and proc.info["name"].lower() in target_names:
                    return proc.info["pid"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None
