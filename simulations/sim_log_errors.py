"""Simulate Crash Type 8: Log-based errors (SEVERE, exceptions, FATAL).

Usage:
  1. Run AutopsyGuard monitor pointing at a case directory
  2. Run this script with the same case directory
  3. Observe AutopsyGuard detecting the errors from the case log

This appends realistic error entries to the case's autopsy.log.0.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

_LOG_ERRORS = {
    "severe": (
        "{ts} SEVERE [org.sleuthkit.autopsy.casemodule.Case]: "
        "Failed to update case database schema\n"
    ),
    "exception": (
        "{ts} WARNING [org.sleuthkit.autopsy.ingest.IngestManager]: "
        "Ingest module error\n"
        "java.io.IOException: Error reading file from data source\n"
        "\tat org.sleuthkit.autopsy.modules.filetypeid."
        "FileTypeIdIngestModule.process(FileTypeIdIngestModule.java:98)\n"
        "\tat org.sleuthkit.autopsy.ingest.IngestManager"
        "$IngestTaskWorker.run(IngestManager.java:889)\n"
    ),
    "fatal": (
        "{ts} FATAL [org.sleuthkit.autopsy.core]: "
        "Unrecoverable error — database corruption detected\n"
    ),
    "stackoverflow": (
        "{ts} SEVERE [org.sleuthkit.autopsy.ingest.IngestManager]: "
        "Ingest thread error\n"
        "java.lang.StackOverflowError\n"
        "\tat java.base/java.util.regex.Pattern$GroupHead.match(Pattern.java:4804)\n"
        "\tat java.base/java.util.regex.Pattern$Loop.match(Pattern.java:4941)\n"
        "\tat java.base/java.util.regex.Pattern$GroupTail.match(Pattern.java:4863)\n"
    ),
}


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python sim_log_errors.py <case_directory> [error_type]")
        print(f"Error types: {', '.join(_LOG_ERRORS.keys())}")
        print('Example: python sim_log_errors.py "C:\\Cases\\MyCase" severe')
        sys.exit(1)

    case_dir = Path(sys.argv[1])
    error_type = sys.argv[2] if len(sys.argv) > 2 else "all"
    log_file = case_dir / "Log" / "autopsy.log.0"

    if not log_file.parent.is_dir():
        print(f"ERROR: Log directory not found: {log_file.parent}")
        sys.exit(1)

    ts = time.strftime("%Y-%m-%d %H:%M:%S")

    if error_type == "all":
        entries = _LOG_ERRORS.values()
    elif error_type in _LOG_ERRORS:
        entries = [_LOG_ERRORS[error_type]]
    else:
        print(f"Unknown error type: {error_type}")
        print(f"Available: {', '.join(_LOG_ERRORS.keys())}")
        sys.exit(1)

    with open(log_file, "a", encoding="utf-8") as f:
        for entry in entries:
            f.write(entry.format(ts=ts))

    print(f"Appended {error_type} error(s) to: {log_file}")
    print()
    print("AutopsyGuard should now detect:")
    print("  - LOG_ERROR and/or OUT_OF_MEMORY events")


if __name__ == "__main__":
    main()
