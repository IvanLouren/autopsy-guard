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
            if name in target_names:
                return proc.info["pid"]

            if name in java_names:
                cmdline = proc.info.get("cmdline") or []
                if any("autopsy" in str(arg).lower() for arg in cmdline):
                    return proc.info["pid"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return None
