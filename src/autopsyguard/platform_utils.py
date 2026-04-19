"""Cross-platform helpers for Autopsy paths and process identification."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def is_windows() -> bool:
    return sys.platform == "win32"


def get_autopsy_process_names() -> list[str]:
    """Return the process names used by Autopsy on the current platform."""
    if is_windows():
        return ["autopsy64.exe", "autopsy.exe"]
    return ["autopsy"]


# `find_autopsy_pid` is implemented centrally in `utils.process_utils`.
# This module exposes platform helpers (names/paths) used by that function.


def get_java_process_names() -> list[str]:
    """Return Java process names that Autopsy spawns as children."""
    if is_windows():
        return ["java.exe", "javaw.exe"]
    return ["java"]


def get_autopsy_user_dir() -> Path:
    """Return the global Autopsy user-data directory.

    Windows: %APPDATA%/autopsy
    Linux:   ~/.autopsy
    """
    if is_windows():
        appdata = os.environ.get("APPDATA", "")
        return Path(appdata) / "autopsy"
    return Path.home() / ".autopsy"


def get_autopsy_log_dir() -> Path:
    """Return the global Autopsy log directory."""
    return get_autopsy_user_dir() / "var" / "log"


def get_case_log_dir(case_dir: Path) -> Path:
    """Return the log directory inside a specific Autopsy case."""
    return case_dir / "Log"


def get_case_lock_file(case_dir: Path) -> Path:
    """Return the path to the case log lock file.

    This file is present while the case is actively open.
    A stale lock file after the process disappears indicates a crash.
    """
    return get_case_log_dir(case_dir) / "autopsy.log.0.lck"


def get_case_log_file(case_dir: Path) -> Path:
    """Return the path to the main case log file."""
    return get_case_log_dir(case_dir) / "autopsy.log.0"


def get_hs_err_search_dirs(autopsy_install_dir: Path | None = None) -> list[Path]:
    """Return directories where JVM hs_err_pid*.log files may appear.

    The JVM writes these to the process working directory or user home
    on a fatal crash (SIGSEGV, SIGBUS, etc.).
    """
    dirs = [Path.home()]
    if autopsy_install_dir is not None:
        dirs.append(autopsy_install_dir)
        dirs.append(autopsy_install_dir / "bin")
    return dirs


def validate_case_dir(case_dir: Path) -> bool:
    """Check that a path looks like a valid Autopsy case directory.

    A valid case directory contains a .aut file and an autopsy.db.
    """
    if not case_dir.is_dir():
        return False
    has_aut = any(case_dir.glob("*.aut"))
    has_db = (case_dir / "autopsy.db").exists()
    return has_aut and has_db
