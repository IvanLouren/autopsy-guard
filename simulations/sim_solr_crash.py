"""Simulate Crash Type 5: Solr Subprocess Crash.

Usage:
  1. Start Autopsy and open a case (keyword search must be active)
  2. Run AutopsyGuard monitor in another terminal
  3. Run this script — it finds and kills only the Solr child Java process
  4. Observe AutopsyGuard detecting the child process disappearance

This simulates the Solr keyword search engine crashing mid-analysis.

NOTE: On Windows, Autopsy may launch Solr through intermediate scripts,
so the Java process may not be a direct child of autopsy64.exe.  This
script also scans system-wide for java.exe processes whose command line
references both "autopsy" and "solr".
"""

from __future__ import annotations

import sys

import psutil

from autopsyguard.platform_utils import get_autopsy_process_names, get_java_process_names


def _find_solr_processes(autopsy_pid: int) -> list[psutil.Process]:
    """Find Solr-related Java processes using two strategies."""
    java_names = [n.lower() for n in get_java_process_names()]
    found: dict[int, psutil.Process] = {}

    # Strategy 1: direct children of the Autopsy process
    try:
        parent = psutil.Process(autopsy_pid)
        for child in parent.children(recursive=True):
            try:
                if child.name().lower() in java_names:
                    found[child.pid] = child
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    # Strategy 2: system-wide scan for java processes with autopsy+solr in cmdline
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = proc.info["name"]
            if not name or name.lower() not in java_names:
                continue
            if proc.info["pid"] in found:
                continue
            cmdline = " ".join(proc.cmdline()).lower()
            if "autopsy" in cmdline and "solr" in cmdline:
                found[proc.info["pid"]] = proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return list(found.values())


def main() -> None:
    # Find the Autopsy parent process
    target_names = [n.lower() for n in get_autopsy_process_names()]
    autopsy_proc = None
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] and proc.info["name"].lower() in target_names:
                autopsy_proc = proc
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if autopsy_proc is None:
        print("ERROR: No Autopsy process found. Start Autopsy first.")
        sys.exit(1)

    print(f"Found Autopsy: {autopsy_proc.name()} (PID {autopsy_proc.pid})")

    # Find Java/Solr processes
    java_children = _find_solr_processes(autopsy_proc.pid)

    if not java_children:
        print("No Java/Solr processes found.")
        print("Make sure you have started an ingest job with Keyword Search enabled.")
        sys.exit(1)

    print(f"Found {len(java_children)} Java process(es):")
    for i, child in enumerate(java_children):
        try:
            cmdline = " ".join(child.cmdline())
            is_solr = "solr" in cmdline.lower()
            label = " [SOLR]" if is_solr else ""
            print(f"  [{i}] PID {child.pid}{label}: {cmdline[:120]}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            print(f"  [{i}] PID {child.pid}: (unavailable)")

    if len(java_children) == 1:
        target = java_children[0]
    else:
        choice = input(f"Which process to kill? [0-{len(java_children)-1}] ").strip()
        try:
            target = java_children[int(choice)]
        except (ValueError, IndexError):
            print("Invalid choice. Aborted.")
            sys.exit(1)

    confirm = input(f"Kill Java process PID {target.pid}? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    target.kill()
    print(f"Killed Java process PID {target.pid}")
    print()
    print("AutopsyGuard should now detect:")
    print("  - SOLR_CRASH event (WARNING)")


if __name__ == "__main__":
    main()

