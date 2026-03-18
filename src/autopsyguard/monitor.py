"""
AutopsyGuard

Usage:
    python monitor.py <case_dir> [--install-dir <path>] [--poll-interval <secs>]
"""

import argparse
import logging
import sys
import time
from pathlib import Path

import psutil

from autopsyguard.config import MonitorConfig
from autopsyguard.platform_utils import (
    find_autopsy_process,
    get_autopsy_log_dir,
    get_case_lock_file,
    get_case_log_file,
    get_hs_err_search_dirs,
    get_java_process_names,
    validate_case_dir,
)

class AutopsyDetector:
    def __init__(self, config: MonitorConfig):
        self.config = config
        
        # Process State
        self.pid = None               # tracked Autopsy PID
        self.children = set()         # tracked Java child PIDs
        self.pid_lost = False         # already reported process loss?
        self.known_hs = set()         # hs_err files we already know about
        self.hs_ready = False         # first scan done?
        self.log_pos = {}             # file -> read offset
        self.logs_ready = False       # first scan done?
        
        # Hang checking state
        self.low_cpu_start = None     # when CPU went low
        self.log_stale_start = None   # when log stopped updating
        self.last_log_mod = None      # last log mtime
        self.hang_flagged = False
        
        # High resource checking state
        self.high_cpu_start = None
        self.cpu_flagged = False
        self.mem_flagged = False
        self.disk_flagged = False

    def check_process(self):
        if self.pid is None:
            self.pid = find_autopsy_process()
            if self.pid:
                logging.info("Found Autopsy (PID %d)", self.pid)
                self.pid_lost = False
                self.children = self._get_java_children(self.pid)
            else:
                if get_case_lock_file(self.config.case_dir).exists():
                    logging.warning("[PROCESS_DISAPPEARED] Lock file present but Autopsy not running")
            return

        if not psutil.pid_exists(self.pid):
            if not self.pid_lost:
                logging.critical("[PROCESS_DISAPPEARED] PID %d is gone!", self.pid)
                if get_case_lock_file(self.config.case_dir).exists():
                    logging.warning("  └─ Lock file still exists — ungraceful shutdown")
                self.pid_lost = True
            self.pid = None
            self.children.clear()
            return

        self._check_children()

    def _get_java_children(self, parent_pid):
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

    def _check_children(self):
        if self.pid is None:
            return
        now = self._get_java_children(self.pid)
        if self.children:
            for lost in self.children - now:
                logging.warning("[SOLR_CRASH] Java process PID %d disappeared (possible Solr crash)", lost)
        self.children = now

    def check_jvm_crash(self):
        found = set()
        for d in get_hs_err_search_dirs(self.config.autopsy_install_dir):
            if d.is_dir():
                found.update(f.resolve() for f in d.glob("hs_err_pid*.log"))

        if not self.hs_ready:
            self.known_hs = found
            self.hs_ready = True
            return

        for f in found - self.known_hs:
            logging.critical("[JVM_CRASH] New crash file: %s", f)
        self.known_hs = found

    def check_logs(self):
        files = self._collect_log_files()

        if not self.logs_ready:
            for f in files:
                self.log_pos[f] = f.stat().st_size
            self.logs_ready = True
            logging.info("Watching %d log file(s)", len(files))
            return

        for f in files:
            self._scan_log(f)

    def _collect_log_files(self):
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

    def _scan_log(self, path):
        if not path.is_file():
            return
        try:
            size = path.stat().st_size
        except OSError:
            return

        offset = self.log_pos.get(path, 0)
        if size < offset:
            offset = 0  # file rotated
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
                logging.critical("[OUT_OF_MEMORY] %s", path.name)
            elif "StackOverflowError" in line:
                logging.critical("[LOG_ERROR] StackOverflowError in %s", path.name)
            elif "FATAL" in line:
                logging.critical("[LOG_ERROR] FATAL in %s", path.name)
            elif "SEVERE" in line:
                logging.warning(
                    "[LOG_ERROR] SEVERE in %s: %s",
                    path.name,
                    line.strip()[:300],
                )

    def check_hang(self):
        now = time.time()

        if self.pid is not None:
            try:
                cpu = psutil.Process(self.pid).cpu_percent(interval=0.1)
                if cpu <= self.config.hang_cpu_threshold:
                    if self.low_cpu_start is None:
                        self.low_cpu_start = now
                    elif now - self.low_cpu_start >= self.config.hang_timeout and not self.hang_flagged:
                        logging.warning("[HANG] CPU at %.1f%% for %ds", cpu, now - self.low_cpu_start)
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
                    logging.warning("[HANG] Log not updated for %ds", now - self.log_stale_start)
                    self.hang_flagged = True

    def check_resources(self):
        now = time.time()

        if self.pid is not None:
            try:
                proc = psutil.Process(self.pid)

                cpu = proc.cpu_percent(interval=0.1)
                if cpu >= self.config.cpu_warning_percent:
                    if self.high_cpu_start is None:
                        self.high_cpu_start = now
                    elif now - self.high_cpu_start >= self.config.cpu_warning_duration and not self.cpu_flagged:
                        logging.warning("[HIGH_RESOURCE] CPU at %.1f%% for %ds", cpu, now - self.high_cpu_start)
                        self.cpu_flagged = True
                else:
                    self.high_cpu_start = None
                    self.cpu_flagged = False

                rss = proc.memory_info().rss
                total = psutil.virtual_memory().total
                pct = (rss / total) * 100
                if pct >= self.config.memory_warning_percent and not self.mem_flagged:
                    logging.warning("[HIGH_RESOURCE] Memory at %.1f%% (%.1f GB)", pct, rss / 1024**3)
                    self.mem_flagged = True
                elif pct < self.config.memory_warning_percent:
                    self.mem_flagged = False

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        try:
            free = psutil.disk_usage(str(self.config.case_dir)).free / 1024**3
            if free < self.config.disk_min_free_gb and not self.disk_flagged:
                logging.critical("[HIGH_RESOURCE] Only %.2f GB free!", free)
                self.disk_flagged = True
            elif free >= self.config.disk_min_free_gb:
                self.disk_flagged = False
        except OSError:
            pass


class Monitor:
    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self.detector = AutopsyDetector(config)

    def run(self) -> None:
        if not validate_case_dir(self.config.case_dir):
            print(f"Error: '{self.config.case_dir}' doesn't look like an Autopsy case directory.")
            return

        try:
            while True:
                self.detector.check_process()
                self.detector.check_jvm_crash()
                self.detector.check_logs()
                self.detector.check_hang()
                self.detector.check_resources()
                time.sleep(self.config.poll_interval)
        except KeyboardInterrupt:
            print("\nStopped.")


def main():
    parser = argparse.ArgumentParser(description="AutopsyGuard — Simple Monitor")
    parser.add_argument("case_dir", type=Path)
    parser.add_argument("--install-dir", type=Path, default=None)
    parser.add_argument("--poll-interval", type=float, default=10.0)
    args = parser.parse_args()

    if not validate_case_dir(args.case_dir):
        print(f"Error: '{args.case_dir}' doesn't look like an Autopsy case directory.")
        sys.exit(1)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    print(f"AutopsyGuard monitoring: {args.case_dir}")
    print(f"Poll every {args.poll_interval}s — Ctrl+C to stop\n")

    config = MonitorConfig(
        case_dir=args.case_dir,
        autopsy_install_dir=args.install_dir,
        poll_interval=args.poll_interval
    )
    
    monitor = Monitor(config)
    monitor.run()

if __name__ == "__main__":
    main()