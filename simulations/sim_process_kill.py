"""Simulate Crash Type 1: Process Disappearance (sudden kill).

Usage:
  1. Start Autopsy and open a case
  2. Run AutopsyGuard monitor in another terminal
  3. Run this script — it finds and force-kills the Autopsy process
  4. Observe AutopsyGuard detecting the disappearance + stale lock file

This simulates scenarios like: power failure, OS crash, external kill.
"""

from __future__ import annotations

import sys

import psutil

from autopsyguard.platform_utils import get_autopsy_process_names


def find_autopsy() -> psutil.Process | None:
    target_names = [n.lower() for n in get_autopsy_process_names()]
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] and proc.info["name"].lower() in target_names:
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def main() -> None:
    proc = find_autopsy()
    if proc is None:
        print("ERROR: No Autopsy process found. Start Autopsy first.")
        sys.exit(1)

    pid = proc.pid
    name = proc.name()
    print(f"Found Autopsy process: {name} (PID {pid})")

    confirm = input("Force-kill this process? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    # Kill the entire process tree (Autopsy + Java children)
    children = proc.children(recursive=True)
    for child in children:
        try:
            print(f"  Killing child: {child.name()} (PID {child.pid})")
            child.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    proc.kill()
    print(f"Killed {name} (PID {pid})")
    print()
    print("AutopsyGuard should now detect:")
    print("  - PROCESS_DISAPPEARED event (CRITICAL)")
    print("  - Stale lock file in the case Log/ directory")


if __name__ == "__main__":
    main()
