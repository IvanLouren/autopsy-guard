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


def check_jvm_crash(install_dir: Path | None) -> None:
    """Detect new JVM crash logs (hs_err_pid*.log)."""
    global known_hs, hs_ready

    found: set[Path] = set()
    for directory in get_hs_err_search_dirs(install_dir):
        if directory.is_dir():
            found.update(p.resolve() for p in directory.glob("hs_err_pid*.log"))

    if not hs_ready:
        known_hs = found
        hs_ready = True
        return

    for crash_file in found - known_hs:
        logging.critical("[JVM_CRASH] New crash file: %s", crash_file)

    known_hs = found

def check_process(case_dir: Path, last_state: bool | None) -> bool:
    """Log when Autopsy starts/stops. Return current running state."""
    pid = find_autopsy_process()
    running = pid is not None

    if running != last_state:
        if running:
            logging.info("Autopsy started (PID %s)", pid)
        else:
            logging.warning("Autopsy stopped or not running")
            if get_case_lock_file(case_dir).exists():
                logging.warning("Lock file still present — possible crash")

    return running

# ── Main ────────────────────────────────────────────────────────────────────

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

    last_state: bool | None = None
    try:
        while True:
            last_state = check_process(args.case_dir, last_state)
            check_jvm_crash(args.install_dir)
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
monitor.py