"""Cross-platform helpers for Autopsy paths and process identification."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def is_windows() -> bool:
    return sys.platform == "win32"



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