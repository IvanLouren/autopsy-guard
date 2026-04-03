"""Detect JVM fatal crashes via hs_err_pid log files.

Covers crash type 2: JVM Crash (HotSpot Error).

When the JVM hits a fatal error (SIGSEGV, SIGBUS, internal error), it writes
a diagnostic file named ``hs_err_pid<PID>.log`` to the working directory or
user home.  This detector watches known directories for new files.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from pathlib import Path

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.platform_utils import get_hs_err_search_dirs

logger = logging.getLogger(__name__)


class JvmCrashDetector(BaseDetector):
    """Monitors for JVM hs_err_pid*.log files indicating a HotSpot crash."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__(config)
        # Track files we've already reported so we don't duplicate
        self._known_files: set[Path] = set()
        # On startup, snapshot existing files so we only report new ones
        self._initialised = False

    @property
    def name(self) -> str:
        return "JvmCrashDetector"

    def check(self) -> list[CrashEvent]:
        search_dirs = get_hs_err_search_dirs(self.config.autopsy_install_dir)
        current_files = self._scan(search_dirs)

        if not self._initialised:
            # First run: record existing files without alerting
            self._known_files = current_files
            self._initialised = True
            logger.debug("JvmCrashDetector: %d pre-existing hs_err files", len(current_files))
            return []

        new_files = current_files - self._known_files
        events: list[CrashEvent] = []

        for path in new_files:
            summary = self._parse_summary(path)
            events.append(CrashEvent(
                crash_type=CrashType.JVM_CRASH,
                severity=Severity.CRITICAL,
                message=f"JVM fatal crash detected: {path.name}",
                details={
                    "file": str(path),
                    "summary": summary,
                },
            ))
            logger.critical("New hs_err file: %s", path)

        self._known_files = current_files
        return events

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _scan(directories: list[Path]) -> set[Path]:
        """Find all hs_err_pid*.log files in the given directories."""
        found: set[Path] = set()
        for directory in directories:
            if not directory.is_dir():
                continue
            for f in directory.glob("hs_err_pid*.log"):
                if f.is_file():
                    found.add(f.resolve())
        return found

    @staticmethod
    def _parse_summary(path: Path) -> str:
        """Extract the first few meaningful lines from an hs_err file.

        The file starts with a header like:
            # A fatal error has been detected by the Java Runtime Environment:
            #
            #  SIGSEGV (0xb) at pc=0x00007f..., pid=12345, tid=67890
            #
            # JRE version: ...
        """
        lines: list[str] = []
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh):
                    if i >= 15:
                        break
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        stripped = stripped.lstrip("# ").strip()
                    if stripped:
                        lines.append(stripped)
        except OSError as exc:
            return f"(could not read file: {exc})"
        return "\n".join(lines)
