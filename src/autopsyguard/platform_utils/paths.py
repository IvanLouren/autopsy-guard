"""Platform-specific path resolution for Autopsy config, logs, and state."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from autopsyguard.platform_utils.process import is_windows


def get_autopsy_user_dir() -> Path:
    """Return the global Autopsy user-data directory.

    Windows: %APPDATA%/autopsy
    Linux:   ~/.autopsy
    """
    if is_windows():
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "autopsy"
        return Path.home() / "AppData" / "Roaming" / "autopsy"
        
    snap_user_common = os.environ.get("SNAP_USER_COMMON")
    if snap_user_common:
        snap_autopsy = Path(snap_user_common) / ".autopsy"
        snap_dev = snap_autopsy / "dev"
        if snap_dev.exists():
            return snap_dev
        if snap_autopsy.exists():
            return snap_autopsy

    home_snap_dev = Path.home() / "snap" / "autopsy" / "common" / ".autopsy" / "dev"
    if home_snap_dev.exists():
        return home_snap_dev
    home_snap = Path.home() / "snap" / "autopsy" / "common" / ".autopsy"
    if home_snap.exists():
        return home_snap

    return Path.home() / ".autopsy"


def get_autopsy_log_dir() -> Path:
    """Return the global Autopsy log directory."""
    user_dir = get_autopsy_user_dir()
    log_paths: list[Path]
    user_dir_name = user_dir.name.lower()
    normalized_user_dir_name = user_dir_name.lstrip(".")

    if user_dir_name == "dev":
        log_paths = [
            user_dir / "var" / "log",
            user_dir.parent / "var" / "log",
        ]
    elif normalized_user_dir_name == "autopsy":
        log_paths = [
            user_dir / "dev" / "var" / "log",
            user_dir / "var" / "log",
        ]
    else:
        log_paths = [user_dir / "var" / "log"]

    for p in log_paths:
        if p.is_dir():
            return p
    return log_paths[0]


def get_case_log_dir(case_dir: Path) -> Path:
    """Return the log directory inside a specific Autopsy case."""
    return case_dir / "Log"


def get_case_lock_file(case_dir: Path) -> Path:
    """Return the path to the case log lock file."""
    return get_case_log_dir(case_dir) / "autopsy.log.0.lck"


def get_global_lock_file() -> Path:
    """Return the global NetBeans/messages lock file used by Autopsy."""
    return get_autopsy_log_dir() / "messages.log.lck"


def get_case_log_file(case_dir: Path) -> Path:
    """Return the path to the main case log file."""
    return get_case_log_dir(case_dir) / "autopsy.log.0"


def get_hs_err_search_dirs(autopsy_install_dir: Path | None = None) -> list[Path]:
    """Return directories where JVM hs_err_pid*.log files may appear."""
    dirs: list[Path] = [Path.home()]
    if autopsy_install_dir is not None:
        dirs.append(autopsy_install_dir)
        dirs.append(autopsy_install_dir / "bin")

    try:
        from autopsyguard.utils.process_utils import find_autopsy_pid
        pid = find_autopsy_pid()
        if pid is not None:
            try:
                import psutil
                try:
                    proc_cwd = Path(psutil.Process(pid).cwd())
                    if proc_cwd.exists():
                        dirs.append(proc_cwd)
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    pass
            except Exception:
                pass
    except Exception:
        pass

    if not is_windows():
        dirs.append(Path("/tmp"))

    return dirs


def get_autopsyguard_state_dir(case_dir: Path) -> Path:
    """Return a state directory outside the case, namespaced by a hash of the case path."""
    case_hash = hashlib.sha256(str(case_dir.resolve()).encode()).hexdigest()[:16]
    return get_autopsy_user_dir() / "autopsyguard" / case_hash
