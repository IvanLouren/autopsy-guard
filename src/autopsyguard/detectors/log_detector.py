"""Detect errors and anomalies by tailing Autopsy log files.

Covers crash types:
  3. OutOfMemoryError — detected via log pattern
  8. Log-Based Error Detection — SEVERE, exceptions, fatal messages
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.platform_utils import get_autopsy_log_dir, get_case_log_file

logger = logging.getLogger(__name__)

# Specific patterns that warrant CRITICAL severity
_OOM_PATTERN = re.compile(r"java\.lang\.OutOfMemoryError", re.IGNORECASE)
_STACK_OVERFLOW_PATTERN = re.compile(r"java\.lang\.StackOverflowError", re.IGNORECASE)
_FATAL_PATTERN = re.compile(r"\bFATAL\b", re.IGNORECASE)


class LogDetector(BaseDetector):
    """Tails Autopsy log files and detects error patterns."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__(config)
        # Map from file path → byte offset we've read up to
        self._file_offsets: dict[Path, int] = {}
        self._initialised = False

    @property
    def name(self) -> str:
        return "LogDetector"

    def check(self) -> list[CrashEvent]:
        log_files = self._get_log_files()

        if not self._initialised:
            # Seek to end of all files on first run so we only catch new errors
            for log_file in log_files:
                if log_file.is_file():
                    self._file_offsets[log_file] = log_file.stat().st_size
            self._initialised = True
            logger.debug("LogDetector: tracking %d log file(s)", len(log_files))
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

        try:
            current_size = path.stat().st_size
        except OSError:
            return events

        last_offset = self._file_offsets.get(path, 0)

        # Handle log rotation (file got smaller)
        if current_size < last_offset:
            last_offset = 0

        if current_size == last_offset:
            return events

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(last_offset)
                new_text = fh.read()
                self._file_offsets[path] = fh.tell()
        except OSError as exc:
            logger.warning("Could not read %s: %s", path, exc)
            return events

        for line in new_text.splitlines():
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
