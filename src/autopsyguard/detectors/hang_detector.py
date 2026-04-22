"""Detect Autopsy application hangs/freezes.

Covers crash type 4: Application Hang/Freeze.

A hang is detected when MULTIPLE signals occur together:
  - CPU usage near zero for an extended period while the process is alive
  - Log files stop being written to for an extended period
  - Solr service is unresponsive or slow

A single signal alone (e.g., low CPU) is NOT sufficient - Autopsy may be
legitimately idle waiting for user input or after completing processing.
"""

from __future__ import annotations

import logging
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import TypedDict

import psutil

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.platform_utils import get_autopsy_log_dir, get_case_log_file
from autopsyguard.utils.process_utils import find_autopsy_pid

logger = logging.getLogger(__name__)


class CpuSignal(TypedDict):
    """Signal indicating CPU is suspiciously low."""
    pid: int
    cpu: float
    duration: float


class LogSignal(TypedDict):
    """Signal indicating log files have stopped being written."""
    stale_seconds: float
    last_mtime: float


class SolrSignal(TypedDict, total=False):
    """Signal indicating Solr is unresponsive or slow.

    `response_time` is optional and only populated when `status` == "slow".
    Marking the TypedDict as `total=False` reflects this optionality and
    avoids invalid default-value syntax in the class body.
    """
    status: str  # "slow", "unresponsive"
    response_time: float | None  # Only for "slow" status


class HangDetector(BaseDetector):
    """Detects application hangs via correlation of multiple signals.
    
    Hang detection requires at least 2 of 3 signals to trigger:
      1. CPU near zero for extended period
      2. Log files not updated for extended period  
      3. Solr service unresponsive
    
    This prevents false positives when Autopsy is legitimately idle.
    """

    def __init__(self, config: MonitorConfig, solr_cache=None) -> None:
        super().__init__(config)
        self._solr_cache = solr_cache
        # CPU tracking
        self._low_cpu_start: float | None = None
        self._last_cpu_value: float | None = None
        
        # Log tracking
        self._log_stale_start: float | None = None
        self._last_log_mtime: float | None = None
        
        # Solr tracking
        self._solr_unresponsive_start: float | None = None
        
        # Hang state
        self._hang_reported = False
        self._hang_start_time: float | None = None
        
        # Process restart tracking
        self._last_known_pid: int | None = None

    @property
    def name(self) -> str:
        return "HangDetector"

    def check(self) -> list[CrashEvent]:
        events: list[CrashEvent] = []
        now = time.time()

        # Check for process restart and reset state if needed
        current_pid = find_autopsy_pid()
        if current_pid != self._last_known_pid:
            if self._last_known_pid is not None:
                # Process restarted - reset all hang tracking state
                logger.debug("Autopsy process restarted (PID %s -> %s), resetting hang state", 
                            self._last_known_pid, current_pid)
                self._reset_hang_state()
            self._last_known_pid = current_pid

        # Collect signals (fetch PID once and pass through)
        cpu_signal = self._check_cpu_signal(now, current_pid)
        log_signal = self._check_log_signal(now)
        solr_signal = self._check_solr_signal(now)
        
        # Count active signals
        signals = [cpu_signal, log_signal, solr_signal]
        active_signals = sum(1 for s in signals if s is not None)
        
        # Need at least 2 signals to declare a hang
        if active_signals >= 2 and not self._hang_reported:
            if self._hang_start_time is None:
                self._hang_start_time = now
            
            hang_duration = now - self._hang_start_time
            
            # Only report after sustained correlation
            if hang_duration >= self.config.hang_confirmation_duration:
                signal_names = []
                if cpu_signal:
                    signal_names.append(f"CPU {cpu_signal['cpu']:.1f}%")
                if log_signal:
                    signal_names.append(f"logs stale {log_signal['stale_seconds']:.0f}s")
                if solr_signal:
                    signal_names.append(f"Solr {solr_signal['status']}")
                
                events.append(CrashEvent(
                    crash_type=CrashType.HANG,
                    severity=Severity.CRITICAL,
                    message=f"Possible hang detected: {', '.join(signal_names)}",
                    details={
                        "signals_active": active_signals,
                        "cpu_signal": cpu_signal,
                        "log_signal": log_signal,
                        "solr_signal": solr_signal,
                        "hang_duration": hang_duration,
                    },
                ))
                self._hang_reported = True
        
        elif active_signals < 2:
            # Signals cleared - reset hang tracking
            self._hang_start_time = None
            if self._hang_reported:
                logger.info("Hang condition cleared")
                self._hang_reported = False

        return events

    def _check_cpu_signal(self, now: float, pid: int | None) -> CpuSignal | None:
        """Check if CPU usage is suspiciously low.

        The PID is supplied by the caller to avoid performing multiple
        expensive process scans per poll cycle. If `pid` is None the
        method clears internal CPU-tracking state and returns None.
        """
        if pid is None:
            self._low_cpu_start = None
            self._last_cpu_value = None
            return None

        try:
            proc = psutil.Process(pid)
            # Use non-blocking measurement to avoid adding 100ms blocking
            # per detector call. `interval=None` returns percent since the
            # last call for this process; the first call may return 0.0.
            # This trade-off reduces latency at short `poll_interval` values.
            cpu = proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._low_cpu_start = None
            return None

        # Discard the first sample after PID discovery — psutil returns 0.0
        # on the first call for a process, which would otherwise start the
        # low-CPU timer too early and may cause false-positive hang detection.
        if self._last_cpu_value is None:
            try:
                self._last_cpu_value = float(cpu)
            except Exception:
                self._last_cpu_value = 0.0
            return None

        self._last_cpu_value = cpu
        
        if cpu <= self.config.hang_cpu_threshold:
            if self._low_cpu_start is None:
                self._low_cpu_start = now
            
            elapsed = now - self._low_cpu_start
            if elapsed >= self.config.hang_timeout:
                return {
                    "pid": pid,
                    "cpu": cpu,
                    "duration": elapsed,
                }
        else:
            # CPU is active - reset
            self._low_cpu_start = None

        return None

    def _check_log_signal(self, now: float) -> LogSignal | None:
        """Check if log files have stopped being written.

        Returns signal dict if logs haven't been updated for timeout period.
        """
        log_files = self._get_monitored_logs()
        if not log_files:
            return None

        try:
            latest_mtime = max(
                (f.stat().st_mtime for f in log_files if f.is_file()),
                default=None,
            )
        except OSError:
            return None
            
        if latest_mtime is None:
            return None

        # First run - just record the mtime
        if self._last_log_mtime is None:
            self._last_log_mtime = latest_mtime
            return None

        if latest_mtime > self._last_log_mtime:
            # Logs are being written - reset
            self._last_log_mtime = latest_mtime
            self._log_stale_start = None
            return None

        # Logs haven't changed
        if self._log_stale_start is None:
            self._log_stale_start = now

        stale_duration = now - self._log_stale_start
        if stale_duration >= self.config.log_stale_timeout:
            return {
                "stale_seconds": stale_duration,
                "last_mtime": latest_mtime,
            }

        return None

    def _check_solr_signal(self, now: float) -> SolrSignal | None:
        """Check if Solr is unresponsive or responding slowly.
        
        Args:
            now: Current timestamp (unused but maintained for consistency).
            
        Returns:
            SolrSignal dict with status ("slow"|"unresponsive") and response_time.
            None if Solr is responsive within acceptable time limits.
            
        Side effects:
            Updates self._solr_unresponsive_start timestamp when transitioning 
            from responsive to unresponsive state.
            
        Note:
            Uses `self.config.solr_ping_timeout` for connection timeout.
            Considers response slow if > `self.config.solr_ping_slow_threshold`.
        """
        # Use shared solr cache if provided to avoid duplicate probes and
        # to respect any hang/down reports already emitted by SolrDetector.
        try:
            if self._solr_cache is not None:
                # If SolrDetector already reported a hang or down recently,
                # suppress the Solr signal here to avoid double-alerting.
                suppression_window = max(self.config.hang_confirmation_duration, 1)
                if (self._solr_cache.was_reported_recently("hang", suppression_window)
                        or self._solr_cache.was_reported_recently("down", suppression_window)):
                    # Clear local unresponsive tracking since authoritative detector handled it
                    self._solr_unresponsive_start = None
                    return None

                status = self._solr_cache.get_status()
                if status.is_up:
                    elapsed = status.response_time or 0.0
                    if elapsed > self.config.solr_ping_slow_threshold:
                        if self._solr_unresponsive_start is None:
                            self._solr_unresponsive_start = now

                        if now - self._solr_unresponsive_start >= self.config.solr_ping_slow_duration:
                            return {"status": "slow", "response_time": elapsed}
                    else:
                        self._solr_unresponsive_start = None
                    return None
                else:
                    # Solr not responding according to cache
                    if self._solr_unresponsive_start is None:
                        self._solr_unresponsive_start = now

                    if now - self._solr_unresponsive_start >= self.config.solr_unresponsive_duration:
                        return {"status": "unresponsive"}
                    return None

        except Exception:
            # Fall back to direct probe on unexpected errors
            pass

        # Fallback: perform a direct lightweight ping probe if cache missing/failed
        try:
            cores_url = f"http://localhost:{self.config.solr_port}/solr/admin/cores?action=STATUS&wt=json"
            with urllib.request.urlopen(cores_url, timeout=self.config.solr_ping_timeout) as cresp:
                import json
                data = json.loads(cresp.read())
                cores = list(data.get("status", {}).keys())
                if not cores:
                    raise ValueError("no cores")
                core = cores[0]
                ping_url = f"http://localhost:{self.config.solr_port}/solr/{core}/admin/ping?wt=json"
                start = time.time()
                with urllib.request.urlopen(ping_url, timeout=self.config.solr_ping_timeout) as presp:
                    elapsed = time.time() - start
                    if presp.status == 200:
                        if elapsed > self.config.solr_ping_slow_threshold:
                            if self._solr_unresponsive_start is None:
                                self._solr_unresponsive_start = now
                            if now - self._solr_unresponsive_start >= self.config.solr_ping_slow_duration:
                                return {"status": "slow", "response_time": elapsed}
                        else:
                            self._solr_unresponsive_start = None
                        return None
        except Exception:
            if self._solr_unresponsive_start is None:
                self._solr_unresponsive_start = now
            if now - self._solr_unresponsive_start >= self.config.solr_unresponsive_duration:
                return {"status": "unresponsive"}

        return None

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

    def _reset_hang_state(self) -> None:
        """Reset all hang tracking state when process restarts."""
        self._low_cpu_start = None
        self._last_cpu_value = None
        self._log_stale_start = None
        self._last_log_mtime = None
        self._solr_unresponsive_start = None
        self._hang_reported = False
        self._hang_start_time = None

