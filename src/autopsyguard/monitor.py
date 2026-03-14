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