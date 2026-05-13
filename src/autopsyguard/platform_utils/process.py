"""Platform-specific process identification for Autopsy and its child processes."""

from __future__ import annotations

import sys


def is_windows() -> bool:
    """Return True if running on Windows."""
    return sys.platform == "win32"


def get_autopsy_process_names() -> list[str]:
    """Return the process names used by Autopsy on the current platform."""
    if is_windows():
        return ["autopsy64.exe", "autopsy.exe"]
    return ["autopsy"]


def get_java_process_names() -> list[str]:
    """Return Java process names that Autopsy spawns as children."""
    if is_windows():
        return ["java.exe", "javaw.exe"]
    # On some Linux installs (snap/AppImage) the embedded Solr is started
    # via a launcher script named `autopsy-solr`. That script briefly
    # appears in process listings before exec'ing the JVM. Include it
    # defensively so transient launcher processes are tracked.
    return ["java", "autopsy-solr"]
