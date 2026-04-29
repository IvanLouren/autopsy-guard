"""Process utility functions for detector implementations.

This module provides shared functions for finding and managing Autopsy processes,
eliminating code duplication across multiple detectors.
"""

from __future__ import annotations

import psutil
from pathlib import Path

from autopsyguard.platform_utils import get_autopsy_process_names, get_java_process_names


def find_autopsy_pid() -> int | None:
    """Scan running processes for the Autopsy launcher process.
    
    Returns:
        The PID of the first Autopsy process found, or None if not running.
        
    Notes:
        - Uses platform-specific process names from get_autopsy_process_names()
        - Case-insensitive matching
        - Returns on first match for efficiency
    """
    target_names = {n.lower() for n in get_autopsy_process_names()}
    java_names = {n.lower() for n in get_java_process_names()}

    # Known launcher basenames (script/executable names used by packages)
    launcher_basenames = {"autopsywrapper", "autopsywrapper.sh", "nbexec", "nbexec.sh"}

    for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
        try:
            name = (proc.info.get("name") or "").lower()
            cmdline = proc.info.get("cmdline") or []

            # Exact executable name match for the Autopsy launcher
            if name in target_names:
                return proc.info["pid"]

            # If the process binary itself is a known launcher, accept it
            if name in launcher_basenames:
                return proc.info["pid"]

            # Some launchers run as a shell (e.g. '/bin/sh autopsywrapper.sh'),
            # so inspect the cmdline argument basenames for known launcher names.
            for arg in cmdline:
                try:
                    if Path(str(arg)).name.lower() in launcher_basenames:
                        return proc.info["pid"]
                except Exception:
                    # Ignore weird cmdline entries we can't parse
                    pass

            # Defensive fallback: if the process name contains 'autopsy'
            # return it. This captures uncommon launcher names.
            if "autopsy" in name:
                return proc.info["pid"]

            # Determine whether this process is a JVM by checking:
            # - the process name, or
            # - the basename of the first cmdline entry, or
            # - the executable name when available.
            is_java_proc = False
            try:
                if name in java_names:
                    is_java_proc = True
                else:
                    # Check first cmdline entry basename
                    if cmdline:
                        first = str(cmdline[0])
                        if Path(first).name.lower() in java_names:
                            is_java_proc = True
                    # Check proc.exe filename if available (may raise or be None)
                    exe = proc.info.get("exe")
                    if not is_java_proc and exe:
                        if Path(str(exe)).name.lower() in java_names:
                            is_java_proc = True
            except Exception:
                # Be conservative on errors: assume not Java and continue
                is_java_proc = False

            # If the process looks like a Java VM, run the Java-specific
            # Autopsy checks and then skip the generic 'autopsy' substring
            # scan to avoid false-positives from JVM system properties.
            if is_java_proc:
                cmdline = proc.info.get("cmdline") or []
                for arg in cmdline:
                    s = str(arg).lower()
                    if "org.sleuthkit.autopsy" in s:
                        return proc.info["pid"]
                    # Look for explicit netbeans.user setting that names
                    # an Autopsy user dir: e.g. -J-Dnetbeans.user=/home/.../autopsy
                    if "netbeans.user" in s and "autopsy" in s:
                        return proc.info["pid"]
                    # Branding flag explicitly set to 'autopsy'
                    if "--branding" in s and "autopsy" in s:
                        return proc.info["pid"]
                continue

            # For non-Java processes that didn't match by name, also check
            # the command line for an 'autopsy' substring. This captures
            # wrapper scripts (e.g. autopsywrapper.sh) used by snap/AppImage
            # without relying on exact process names.
            cmdline = proc.info.get("cmdline") or []
            for arg in cmdline:
                if "autopsy" in str(arg).lower():
                    return proc.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return None
