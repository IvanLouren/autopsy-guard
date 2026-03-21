"""Anomaly detection logic for AutopsyGuard."""

import time
from pathlib import Path
from typing import Iterator

import psutil

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.platform_utils import (
    find_autopsy_process,
    get_autopsy_log_dir,
    get_case_lock_file,
    get_case_log_file,
    get_hs_err_search_dirs,
    get_java_process_names,
)


class AnomalyDetector:
    """Core logic to detect anomalies in an Autopsy process and its environment."""

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config

        # Process state
        self.pid: int | None = None
        self.children: set[int] = set()
        self.pid_lost: bool = False

        # Logs and crashes state
        self.known_hs: set[Path] = set()
        self.hs_ready: bool = False
        self.log_pos: dict[Path, int] = {}
        self.logs_ready: bool = False

        # Hang state
        self.low_cpu_start: float | None = None
        self.log_stale_start: float | None = None
        self.last_log_mod: float | None = None
        self.hang_flagged: bool = False

        # Resource state
        self.high_cpu_start: float | None = None
        self.cpu_flagged: bool = False
        self.mem_flagged: bool = False
        self.disk_flagged: bool = False

    def run_all_checks(self) -> Iterator[CrashEvent]:
        """Run all monitoring checks and yield any detected events."""
        yield from self.check_process()
        yield from self.check_jvm_crash()
        yield from self.check_logs()
        yield from self.check_hang()
        yield from self.check_resources()

    def check_process(self) -> Iterator[CrashEvent]:
        """Check if Autopsy and its child processes are running."""
        if self.pid is None:
            self.pid = find_autopsy_process()
            if self.pid:
                self.pid_lost = False
                self.children = self._get_java_children(self.pid)
            else:
                lock_file = get_case_lock_file(self.config.case_dir)
                if lock_file.exists():
                    yield CrashEvent(
                        crash_type=CrashType.PROCESS_DISAPPEARED,
                        severity=Severity.WARNING,
                        message="Lock file present but Autopsy not running (ungraceful shutdown).",
                    )
            return

        if not psutil.pid_exists(self.pid):
            if not self.pid_lost:
                message = f"Autopsy PID {self.pid} is gone!"
                if get_case_lock_file(self.config.case_dir).exists():
                    message += " Lock file still exists (ungraceful shutdown)."
                yield CrashEvent(
                    crash_type=CrashType.PROCESS_DISAPPEARED,
                    severity=Severity.CRITICAL,
                    message=message,
                )
                self.pid_lost = True
            self.pid = None
            self.children.clear()
            return

        yield from self._check_children()

    def _get_java_children(self, parent_pid: int) -> set[int]:
        java_names = [n.lower() for n in get_java_process_names()]
        java_pids = set()

        try:
            p = psutil.Process(parent_pid)
            for child in p.children(recursive=True):
                try:
                    name = child.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if name and name.lower() in java_names:
                    java_pids.add(child.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = proc.info["name"]
                if not name or name.lower() not in java_names:
                    continue
                if proc.info["pid"] in java_pids:
                    continue
                cmdline = " ".join(proc.cmdline()).lower()
                if "autopsy" in cmdline and "solr" in cmdline:
                    java_pids.add(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return java_pids

    def _check_children(self) -> Iterator[CrashEvent]:
        if self.pid is None:
            return
            
        now = self._get_java_children(self.pid)
        if self.children:
            for lost in self.children - now:
                yield CrashEvent(
                    crash_type=CrashType.SOLR_CRASH,
                    severity=Severity.WARNING,
                    message=f"Java process PID {lost} disappeared (possible Solr crash).",
                )
        self.children = now

    def check_jvm_crash(self) -> Iterator[CrashEvent]:
        found = set()
        for d in get_hs_err_search_dirs(self.config.autopsy_install_dir):
            if d.is_dir():
                found.update(f.resolve() for f in d.glob("hs_err_pid*.log"))

        if not self.hs_ready:
            self.known_hs = found
            self.hs_ready = True
            return

        for f in found - self.known_hs:
            yield CrashEvent(
                crash_type=CrashType.JVM_CRASH,
                severity=Severity.CRITICAL,
                message=f"New JVM crash file generated: {f.name}",
            )
        self.known_hs = found

    def check_logs(self) -> Iterator[CrashEvent]:
        files = self._collect_log_files()

        if not self.logs_ready:
            for f in files:
                self.log_pos[f] = f.stat().st_size
            self.logs_ready = True
            return

        for f in files:
            yield from self._scan_log(f)

    def _collect_log_files(self) -> list[Path]:
        files = []
        case_log = get_case_log_file(self.config.case_dir)
        if case_log.is_file():
            files.append(case_log)
            
        gdir = get_autopsy_log_dir()
        if gdir.is_dir():
            for name in ("messages.log", "autopsy.log.0"):
                p = gdir / name
                if p.is_file():
                    files.append(p)
        return files

    def _scan_log(self, path: Path) -> Iterator[CrashEvent]:
        if not path.is_file():
            return
            
        try:
            size = path.stat().st_size
        except OSError:
            return

        offset = self.log_pos.get(path, 0)
        if size < offset:
            offset = 0  
        if size == offset:
            return

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                text = fh.read()
                self.log_pos[path] = fh.tell()
        except OSError:
            return

        for line in text.splitlines():
            if "OutOfMemoryError" in line:
                yield CrashEvent(
                    crash_type=CrashType.OUT_OF_MEMORY,
                    severity=Severity.CRITICAL,
                    message=f"OutOfMemoryError in {path.name}",
                )
            elif "StackOverflowError" in line:
                yield CrashEvent(
                    crash_type=CrashType.LOG_ERROR,
                    severity=Severity.CRITICAL,
                    message=f"StackOverflowError in {path.name}",
                )
            elif "FATAL" in line:
                yield CrashEvent(
                    crash_type=CrashType.LOG_ERROR,
                    severity=Severity.CRITICAL,
                    message=f"FATAL error in {path.name}",
                )
            elif "SEVERE" in line:
                snippet = line.strip()[:300]
                yield CrashEvent(
                    crash_type=CrashType.LOG_ERROR,
                    severity=Severity.WARNING,
                    message=f"SEVERE error in {path.name}: {snippet}",
                )

    def check_hang(self) -> Iterator[CrashEvent]:
        now = time.time()

        if self.pid is not None:
            try:
                cpu = psutil.Process(self.pid).cpu_percent(interval=0.1)
                if cpu <= self.config.hang_cpu_threshold:
                    if self.low_cpu_start is None:
                        self.low_cpu_start = now
                    elif now - self.low_cpu_start >= self.config.hang_timeout and not self.hang_flagged:
                        yield CrashEvent(
                            crash_type=CrashType.HANG, 
                            severity=Severity.WARNING,
                            message=f"CPU at {cpu:.1f}% for {int(now - self.low_cpu_start)}s",
                        )
                        self.hang_flagged = True
                else:
                    self.low_cpu_start = None
                    self.hang_flagged = False
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.low_cpu_start = None

        case_log = get_case_log_file(self.config.case_dir)
        if case_log.is_file():
            mt = case_log.stat().st_mtime
            if self.last_log_mod is None:
                self.last_log_mod = mt
            elif mt > self.last_log_mod:
                self.last_log_mod = mt
                self.log_stale_start = None
            else:
                if self.log_stale_start is None:
                    self.log_stale_start = now
                elif now - self.log_stale_start >= self.config.log_stale_timeout and not self.hang_flagged:
                    yield CrashEvent(
                        crash_type=CrashType.HANG,
                        severity=Severity.WARNING,
                        message=f"Log not updated for {int(now - self.log_stale_start)}s",
                    )
                    self.hang_flagged = True

    def check_resources(self) -> Iterator[CrashEvent]:
        now = time.time()

        if self.pid is not None:
            try:
                proc = psutil.Process(self.pid)

                cpu = proc.cpu_percent(interval=0.1)
                if cpu >= self.config.cpu_warning_percent:
                    if self.high_cpu_start is None:
                        self.high_cpu_start = now
                    elif now - self.high_cpu_start >= self.config.cpu_warning_duration and not self.cpu_flagged:
                        yield CrashEvent(
                            crash_type=CrashType.HIGH_RESOURCE_USAGE,
                            severity=Severity.WARNING,
                            message=f"CPU stuck at {cpu:.1f}% for {int(now - self.high_cpu_start)}s",
                        )
                        self.cpu_flagged = True
                else:
                    self.high_cpu_start = None
                    self.cpu_flagged = False

                rss = proc.memory_info().rss
                total = psutil.virtual_memory().total
                pct = (rss / total) * 100
                if pct >= self.config.memory_warning_percent and not self.mem_flagged:
                    yield CrashEvent(
                        crash_type=CrashType.HIGH_RESOURCE_USAGE,
                        severity=Severity.WARNING,
                        message=f"Memory running high at {pct:.1f}% ({rss / 1024**3:.1f} GB)",
                    )
                    self.mem_flagged = True
                elif pct < self.config.memory_warning_percent:
                    self.mem_flagged = False

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        try:
            free = psutil.disk_usage(str(self.config.case_dir)).free / 1024**3
            if free < self.config.disk_min_free_gb and not self.disk_flagged:
                yield CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.CRITICAL,
                    message=f"Dangerous disk levels: Only {free:.2f} GB left!",
                )
                self.disk_flagged = True
            elif free >= self.config.disk_min_free_gb:
                self.disk_flagged = False
        except OSError:
            pass
