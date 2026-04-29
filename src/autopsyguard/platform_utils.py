"""Cross-platform helpers for Autopsy paths and process identification."""

from __future__ import annotations

import os
import sys
from pathlib import Path
import hashlib


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
    # On some Linux installs (snap/AppImage) the embedded Solr is started
    # via a launcher script named `autopsy-solr`. That script briefly
    # appears in process listings before exec'ing the JVM. Include it
    # defensively so transient launcher processes are tracked.
    return ["java", "autopsy-solr"]


def get_autopsy_user_dir() -> Path:
    """Return the global Autopsy user-data directory.

    Windows: %APPDATA%/autopsy
    Linux:   ~/.autopsy
    """
    if is_windows():
        # Prefer the APPDATA environment variable which typically points
        # to the Roaming profile (e.g. C:\Users\<user>\AppData\Roaming).
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "autopsy"
        # Fallback: construct the usual Roaming path from the user home.
        # This handles rare cases where APPDATA is not set in the environment.
        return Path.home() / "AppData" / "Roaming" / "autopsy"
    snap_user_common = os.environ.get("SNAP_USER_COMMON")
    # If running as a snap, prefer the snap common autopsy dir. Some snap
    # installs may place user data under a channel-specific subdirectory
    # such as `dev` (e.g. ~/snap/autopsy/common/.autopsy/dev). Check for
    # that first, then fall back to the plain .autopsy path.
    if snap_user_common:
        snap_autopsy = Path(snap_user_common) / ".autopsy"
        snap_dev = snap_autopsy / "dev"
        if snap_dev.exists():
            return snap_dev
        if snap_autopsy.exists():
            return snap_autopsy

    # Also try the common user-visible snap layout if SNAP_USER_COMMON
    # isn't set for some reason.
    home_snap_dev = Path.home() / "snap" / "autopsy" / "common" / ".autopsy" / "dev"
    if home_snap_dev.exists():
        return home_snap_dev
    home_snap = Path.home() / "snap" / "autopsy" / "common" / ".autopsy"
    if home_snap.exists():
        return home_snap

    return Path.home() / ".autopsy"


def get_autopsy_log_dir() -> Path:
    """Return the global Autopsy log directory.
    Checks both ~/.autopsy/var/log and ~/.autopsy/dev/var/log, returns the one that exists.
    If both exist, prefers ~/.autopsy/dev/var/log.
    """
    home = Path.home()
    log_paths = [
        home / ".autopsy" / "dev" / "var" / "log",
        home / ".autopsy" / "var" / "log",
    ]
    for p in log_paths:
        if p.is_dir():
            return p
    # Fallback to default (dev path)
    return log_paths[0]


def get_case_log_dir(case_dir: Path) -> Path:
    """Return the log directory inside a specific Autopsy case."""
    return case_dir / "Log"


def get_case_lock_file(case_dir: Path) -> Path:
    """Return the path to the case log lock file.

    This file is present while the case is actively open.
    A stale lock file after the process disappears indicates a crash.
    """
    return get_case_log_dir(case_dir) / "autopsy.log.0.lck"


def get_global_lock_file() -> Path:
    """Return the global NetBeans/messages lock file used by Autopsy.

    On Linux this is typically `~/.autopsy/var/log/messages.log.lck` and
    can indicate Autopsy is actively running even if case log files are
    not yet present.
    """
    return get_autopsy_log_dir() / "messages.log.lck"


def get_case_log_file(case_dir: Path) -> Path:
    """Return the path to the main case log file."""
    return get_case_log_dir(case_dir) / "autopsy.log.0"


def get_hs_err_search_dirs(autopsy_install_dir: Path | None = None) -> list[Path]:
    """Return directories where JVM hs_err_pid*.log files may appear.

    The JVM writes these to the process working directory or user home
    on a fatal crash (SIGSEGV, SIGBUS, etc.).
    """
    dirs: list[Path] = [Path.home()]
    if autopsy_install_dir is not None:
        dirs.append(autopsy_install_dir)
        dirs.append(autopsy_install_dir / "bin")

    # Try to include the running Autopsy process working directory, if available.
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
                    # Can't read process cwd - skip
                    pass
            except Exception:
                # psutil not available or other error - skip adding CWD
                pass
    except Exception:
        # process utilities not available - ignore
        pass

    # JVM fallback location on Unix-like systems
    if not is_windows():
        dirs.append(Path("/tmp"))

    return dirs


def get_autopsyguard_state_dir(case_dir: Path) -> Path:
    """Return a state directory outside the case, namespaced by a hash of the case path.

    This avoids writing state files into the evidence case directory which
    could contaminate forensic evidence or fail on read-only mounts.
    """
    case_hash = hashlib.sha256(str(case_dir.resolve()).encode()).hexdigest()[:16]
    # Return the computed path without creating directories as a side effect.
    # Callers that need to write should create the directory explicitly.
    return get_autopsy_user_dir() / "autopsyguard" / case_hash


def validate_case_dir(case_dir: Path) -> bool:
    """Check that a path looks like a valid Autopsy case directory.
    A valid case directory must contain a .aut descriptor file. In single-
    user installations a local `autopsy.db` will be present, but in
    multi-user (PostgreSQL) deployments the database is remote and
    `autopsy.db` is absent. To support both modes we accept a case that
    either has a local `autopsy.db` or a `Log/` directory.
    """
    if not case_dir.is_dir():
        return False
    if not any(case_dir.glob("*.aut")):
        return False

    has_local_db = (case_dir / "autopsy.db").exists()
    has_log_dir = (case_dir / "Log").is_dir()

    return has_local_db or has_log_dir
