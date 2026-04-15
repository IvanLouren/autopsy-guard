"""Detect errors and anomalies by tailing Autopsy log files.

Covers crash types:
  3. OutOfMemoryError — detected via log pattern
  8. Log-Based Error Detection — SEVERE, exceptions, fatal messages
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.platform_utils import get_autopsy_log_dir, get_case_log_file
from autopsyguard.utils.log_tracker import LogFileTracker

logger = logging.getLogger(__name__)

# Specific patterns that warrant CRITICAL severity
_OOM_PATTERN = re.compile(r"java\.lang\.OutOfMemoryError", re.IGNORECASE)
_STACK_OVERFLOW_PATTERN = re.compile(r"java\.lang\.StackOverflowError", re.IGNORECASE)
_FATAL_PATTERN = re.compile(r"\bFATAL\b", re.IGNORECASE)


class LogDetector(BaseDetector):
    """Tails Autopsy log files and detects error patterns."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__(config)
        
        # Initialize log file tracker with persistence
        state_dir = config.case_dir / ".autopsyguard_state"
        state_file = state_dir / "log_positions.json"
        self._log_tracker = LogFileTracker(state_file=state_file)
        self._log_tracker.load_positions()
        self._initialised = False
        self._recent_duplicate_window = 300.0  # seconds
        self._recent_lines: dict[Path, tuple[str, float]] = {}

    @property
    def name(self) -> str:
        return "LogDetector"

    def check(self) -> list[CrashEvent]:
        log_files = self._get_log_files()

        if not self._initialised:
            # Seek to end of all files on first run so we only catch new errors
            for log_file in log_files:
                if log_file.is_file():
                    # Set position to end of file
                    self._log_tracker._file_offsets[log_file] = log_file.stat().st_size
            self._initialised = True
            logger.debug("LogDetector: tracking %d log file(s)", len(log_files))
            # Save initial positions
            self._log_tracker.save_positions()
            return []

        events: list[CrashEvent] = []
        for log_file in log_files:
            events.extend(self._tail_file(log_file))
        return events

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_log_files(self) -> list[Path]:
        """Collect all log files we should be monitoring."""
        files: list[Path] = []

        # Case-specific log
        case_log = get_case_log_file(self.config.case_dir)
        if case_log.is_file():
            files.append(case_log)

        # Global logs (messages.log and autopsy.log.0)
        global_dir = get_autopsy_log_dir()
        if global_dir.is_dir():
            for name in ("messages.log", "autopsy.log.0"):
                p = global_dir / name
                if p.is_file():
                    files.append(p)

        return files

    def _tail_file(self, path: Path) -> list[CrashEvent]:
        """Read new bytes appended to a log file since last check."""
        events: list[CrashEvent] = []

        if not path.is_file():
            return events

        # Use LogFileTracker for incremental reading
        new_content = self._log_tracker.read_new_content(path)
        
        if new_content:
            # Save positions after reading
            self._log_tracker.save_positions()
            
            for line in new_content.splitlines():
                if self._is_recent_duplicate(line, path):
                    continue
                event = self._classify_line(line, path)
                if event is not None:
                    events.append(event)

        return events

    def _classify_line(self, line: str, source: Path) -> CrashEvent | None:
        """Check a single log line against known error patterns."""
        # OutOfMemoryError — critical
        if _OOM_PATTERN.search(line):
            return CrashEvent(
                crash_type=CrashType.OUT_OF_MEMORY,
                severity=Severity.CRITICAL,
                message=f"OutOfMemoryError detected in {source.name}",
                details={"file": str(source), "line": line.strip()},
            )

        # StackOverflowError — critical
        if _STACK_OVERFLOW_PATTERN.search(line):
            return CrashEvent(
                crash_type=CrashType.LOG_ERROR,
                severity=Severity.CRITICAL,
                message=f"StackOverflowError detected in {source.name}",
                details={"file": str(source), "line": line.strip()},
            )

        # FATAL — critical
        if _FATAL_PATTERN.search(line):
            return CrashEvent(
                crash_type=CrashType.LOG_ERROR,
                severity=Severity.CRITICAL,
                message=f"FATAL error in {source.name}",
                details={"file": str(source), "line": line.strip()},
            )

        # SEVERE — warning
        if "SEVERE" in line:
            return CrashEvent(
                crash_type=CrashType.LOG_ERROR,
                severity=Severity.WARNING,
                message=f"SEVERE error in {source.name}",
                details={"file": str(source), "line": line.strip()},
            )

        # Generic exception (but not just the word in a comment/import)
        # Look for lines that look like a Java exception being thrown
        if re.search(r"Exception[:\s]", line) and not line.strip().startswith("//"):
            return CrashEvent(
                crash_type=CrashType.LOG_ERROR,
                severity=Severity.WARNING,
                message=f"Exception detected in {source.name}",
                details={"file": str(source), "line": line.strip()},
            )

        return None

    def _is_recent_duplicate(self, line: str, source: Path) -> bool:
        """Suppress repeated identical lines within a short window."""
        now = time.time()
        last_entry = self._recent_lines.get(source)
        if last_entry is None:
            self._recent_lines[source] = (line, now)
            return False

        last_line, last_ts = last_entry
        if line == last_line and (now - last_ts) <= self._recent_duplicate_window:
            return True

        self._recent_lines[source] = (line, now)
        return False
