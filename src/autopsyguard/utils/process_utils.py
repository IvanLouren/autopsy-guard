"""Process utility functions for detector implementations.

This module provides shared functions for finding and managing Autopsy processes,
eliminating code duplication across multiple detectors.
"""

from __future__ import annotations

import psutil

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

    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (proc.info.get("name") or "").lower()

            # Accept exact matches from the configured target names
            # or defensive substring matches for common launcher names
            # (e.g. 'autopsywrapper' used by the snap/AppImage packages).
            if name in target_names or "autopsy" in name:
                return proc.info["pid"]

            # If the process is a Java binary, examine the command line
            # for explicit Autopsy indicators (package name or netbeans.user).
            if name in java_names:
                cmdline = proc.info.get("cmdline") or []
                for arg in cmdline:
                    s = str(arg).lower()
                    if "org.sleuthkit.autopsy" in s:
                        return proc.info["pid"]
                    if "netbeans.user" in s and "autopsy" in s:
                        return proc.info["pid"]

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
