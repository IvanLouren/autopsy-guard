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

# ── Settings ────────────────────────────────────────────────────────────────
POLL_INTERVAL = 10       # seconds between checks
HANG_CPU_THRESH = 1.0    # CPU % below this for too long = possible hang
HANG_TIMEOUT = 300       # seconds of low CPU before we alert
LOG_STALE_TIMEOUT = 600  # seconds without log writes before we alert
CPU_HIGH = 95.0          # sustained CPU above this = warning
CPU_HIGH_DURATION = 300  # how long high CPU must last
MEM_HIGH = 90.0          # % of system RAM
DISK_MIN_GB = 1.0        # minimum free disk space in GB

# ── State (globals to keep things simple) ───────────────────────────────────
pid = None               # tracked Autopsy PID
children = set()         # tracked Java child PIDs
pid_lost = False         # already reported process loss?
known_hs = set()         # hs_err files we already know about
hs_ready = False         # first scan done?
log_pos = {}             # file → read offset
logs_ready = False       # first scan done?
low_cpu_start = None     # when CPU went low
log_stale_start = None   # when log stopped updating
last_log_mod = None      # last log mtime
hang_flagged = False
high_cpu_start = None
cpu_flagged = False
mem_flagged = False
disk_flagged = False


def _reset_state() -> None:
    global pid, children, pid_lost
    global known_hs, hs_ready, log_pos, logs_ready
    global low_cpu_start, log_stale_start, last_log_mod, hang_flagged
    global high_cpu_start, cpu_flagged, mem_flagged, disk_flagged

    pid = None
    children = set()
    pid_lost = False
    known_hs = set()
    hs_ready = False
    log_pos = {}
    logs_ready = False
    low_cpu_start = None
    log_stale_start = None
    last_log_mod = None
    hang_flagged = False
    high_cpu_start = None
    cpu_flagged = False
    mem_flagged = False
    disk_flagged = False


# ── Type 1 — Process disappearance ─────────────────────────────────────────

def check_process(case_dir):
    global pid, children, pid_lost

    if pid is None:
        pid = find_autopsy_process()
        if pid:
            logging.info("Found Autopsy (PID %d)", pid)
            pid_lost = False
            children = _get_java_children(pid)
        else:
            # no process — stale lock file means it crashed before
            if get_case_lock_file(case_dir).exists():
                logging.warning("[PROCESS_DISAPPEARED] Lock file present but Autopsy not running")
        return

    if not psutil.pid_exists(pid):
        if not pid_lost:
            logging.critical("[PROCESS_DISAPPEARED] PID %d is gone!", pid)
            if get_case_lock_file(case_dir).exists():
                logging.warning("  └─ Lock file still exists — ungraceful shutdown")
            pid_lost = True
        pid = None
        children.clear()
        return

    # process alive — check children (Type 5)
    _check_children()


# ── Type 5 — Solr / child Java crash ───────────────────────────────────────

def _get_java_children(parent_pid):
    """Find Java processes related to Autopsy.

    Looks in two places:
    1. Direct child processes of the Autopsy launcher (recursive).
    2. System-wide Java processes whose command line references both
       "autopsy" and "solr" — needed on Windows where Autopsy launches
       Solr through intermediate scripts, breaking the parent-child chain.
    """
    java_names = [n.lower() for n in get_java_process_names()]
    java_pids = set()

    # Strategy 1: direct children
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

    # Strategy 2: system-wide scan for Autopsy-related Java (e.g. Solr)
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info["name"]
            if not name or name.lower() not in java_names:
                continue
            if proc.info["pid"] in java_pids:
                continue  # already found as a child
            cmdline = " ".join(proc.cmdline()).lower()
            if "autopsy" in cmdline and "solr" in cmdline:
                java_pids.add(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return java_pids


def _check_children():
    global children
    if pid is None:
        return
    now = _get_java_children(pid)
    if children:
        for lost in children - now:
            logging.warning("[SOLR_CRASH] Java process PID %d disappeared (possible Solr crash)", lost)
    children = now


# ── Type 2 — JVM crash (hs_err_pid files + OOM marker) ─────────────────────

def check_jvm_crash(install_dir):
    global known_hs, hs_ready

    found = set()
    for d in get_hs_err_search_dirs(install_dir):
        if d.is_dir():
            found.update(f.resolve() for f in d.glob("hs_err_pid*.log"))

    # Also check for OOM crash marker file (created by -XX:OnOutOfMemoryError)
    oom_marker = Path.home() / "oom_crash_marker.txt"
    if oom_marker.exists():
        found.add(oom_marker.resolve())

    if not hs_ready:
        known_hs = found
        hs_ready = True
        return

    for f in found - known_hs:
        if "oom_crash_marker" in f.name:
            logging.critical("[JVM_CRASH] OOM crash marker detected: %s", f)
            # Clean up marker file after detection
            try:
                f.unlink()
            except OSError:
                pass
        else:
            logging.critical("[JVM_CRASH] New crash file: %s", f)
    known_hs = found


# ── Types 3 & 8 — Log errors (OOM, SEVERE, FATAL …) ───────────────────────

def check_logs(case_dir):
    global log_pos, logs_ready

    files = _collect_log_files(case_dir)

    # first run: skip to end so we don't alert on old stuff
    if not logs_ready:
        for f in files:
            log_pos[f] = f.stat().st_size
        logs_ready = True
        logging.info("Watching %d log file(s)", len(files))
        return

    for f in files:
        _scan_log(f)


def _collect_log_files(case_dir):
    files = []
    case_log = get_case_log_file(case_dir)
    if case_log.is_file():
        files.append(case_log)
    gdir = get_autopsy_log_dir()
    if gdir.is_dir():
        for name in ("messages.log", "autopsy.log.0"):
            p = gdir / name
            if p.is_file():
                files.append(p)
    return files


def _scan_log(path):
    if not path.is_file():
        return
    try:
        size = path.stat().st_size
    except OSError:
        return

    offset = log_pos.get(path, 0)
    if size < offset:
        offset = 0  # file rotated
    if size == offset:
        return

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            text = fh.read()
            log_pos[path] = fh.tell()
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
            logging.warning("[LOG_ERROR] SEVERE in %s: %.100s", path.name, line.strip())


# ── Type 4 — Hang / Freeze ─────────────────────────────────────────────────

def check_hang(case_dir):
    global low_cpu_start, log_stale_start, last_log_mod, hang_flagged, pid
    now = time.time()

    # CPU check
    if pid is not None:
        try:
            cpu = psutil.Process(pid).cpu_percent(interval=0.1)
            if cpu <= HANG_CPU_THRESH:
                if low_cpu_start is None:
                    low_cpu_start = now
                elif now - low_cpu_start >= HANG_TIMEOUT and not hang_flagged:
                    logging.warning("[HANG] CPU at %.1f%% for %ds", cpu, now - low_cpu_start)
                    hang_flagged = True
            else:
                low_cpu_start = None
                hang_flagged = False
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            low_cpu_start = None

    # log freshness check
    case_log = get_case_log_file(case_dir)
    if case_log.is_file():
        mt = case_log.stat().st_mtime
        if last_log_mod is None:
            last_log_mod = mt
        elif mt > last_log_mod:
            last_log_mod = mt
            log_stale_start = None
        else:
            if log_stale_start is None:
                log_stale_start = now
            elif now - log_stale_start >= LOG_STALE_TIMEOUT and not hang_flagged:
                logging.warning("[HANG] Log not updated for %ds", now - log_stale_start)
                hang_flagged = True


# ── Type 6 — High resource usage ───────────────────────────────────────────

def check_resources(case_dir):
    global high_cpu_start, cpu_flagged, mem_flagged, disk_flagged, pid
    now = time.time()

    if pid is not None:
        try:
            proc = psutil.Process(pid)

            # CPU
            cpu = proc.cpu_percent(interval=0.1)
            if cpu >= CPU_HIGH:
                if high_cpu_start is None:
                    high_cpu_start = now
                elif now - high_cpu_start >= CPU_HIGH_DURATION and not cpu_flagged:
                    logging.warning("[HIGH_RESOURCE] CPU at %.1f%% for %ds", cpu, now - high_cpu_start)
                    cpu_flagged = True
            else:
                high_cpu_start = None
                cpu_flagged = False

            # Memory
            rss = proc.memory_info().rss
            total = psutil.virtual_memory().total
            pct = (rss / total) * 100
            if pct >= MEM_HIGH and not mem_flagged:
                logging.warning("[HIGH_RESOURCE] Memory at %.1f%% (%.1f GB)", pct, rss / 1024**3)
                mem_flagged = True
            elif pct < MEM_HIGH:
                mem_flagged = False

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Disk
    try:
        free = psutil.disk_usage(str(case_dir)).free / 1024**3
        if free < DISK_MIN_GB and not disk_flagged:
            logging.critical("[HIGH_RESOURCE] Only %.2f GB free!", free)
            disk_flagged = True
        elif free >= DISK_MIN_GB:
            disk_flagged = False
    except OSError:
        pass


# ── Main ────────────────────────────────────────────────────────────────────

class Monitor:
    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self._apply_config()

    def _apply_config(self) -> None:
        global POLL_INTERVAL, HANG_CPU_THRESH, HANG_TIMEOUT, LOG_STALE_TIMEOUT
        global CPU_HIGH, CPU_HIGH_DURATION, MEM_HIGH, DISK_MIN_GB

        POLL_INTERVAL = self.config.poll_interval
        HANG_CPU_THRESH = self.config.hang_cpu_threshold
        HANG_TIMEOUT = self.config.hang_timeout
        LOG_STALE_TIMEOUT = self.config.log_stale_timeout
        CPU_HIGH = self.config.cpu_warning_percent
        CPU_HIGH_DURATION = self.config.cpu_warning_duration
        MEM_HIGH = self.config.memory_warning_percent
        DISK_MIN_GB = self.config.disk_min_free_gb
        _reset_state()

    def run(self) -> None:
        if not validate_case_dir(self.config.case_dir):
            print(
                f"Error: '{self.config.case_dir}' doesn't look like an Autopsy case directory."
            )
            return

        try:
            while True:
                check_process(self.config.case_dir)
                check_jvm_crash(self.config.autopsy_install_dir)
                check_logs(self.config.case_dir)
                check_hang(self.config.case_dir)
                check_resources(self.config.case_dir)
                time.sleep(self.config.poll_interval)
        except KeyboardInterrupt:
            print("\nStopped.")

def main():
    parser = argparse.ArgumentParser(description="AutopsyGuard — Simple Monitor")
    parser.add_argument("case_dir", type=Path)
    parser.add_argument("--install-dir", type=Path, default=None)
    parser.add_argument("--poll-interval", type=float, default=POLL_INTERVAL)
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

    try:
        while True:
            check_process(args.case_dir)
            check_jvm_crash(args.install_dir)
            check_logs(args.case_dir)
            check_hang(args.case_dir)
            check_resources(args.case_dir)
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()