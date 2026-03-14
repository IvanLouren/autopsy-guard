"""Phase 1: minimal process monitor for Autopsy."""

from __future__ import annotations

import time
import psutil

PROCESS_NAME = "autopsy64.exe"  # Change to the exact process name on your system
POLL_INTERVAL_SECONDS = 5


def is_autopsy_running() -> bool:
    """Return True if the Autopsy process is running."""
    for proc in psutil.process_iter(["name"]):
        name = proc.info.get("name") or ""
        if name.lower() == PROCESS_NAME.lower():
            return True
    return False


def main() -> None:
    """Run a simple loop that reports when Autopsy starts/stops."""
    last_state = None

    while True:
        running = is_autopsy_running()

        if running != last_state:
            if running:
                print("Autopsy started")
            else:
                print("Autopsy stopped or not running")
            last_state = running

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()