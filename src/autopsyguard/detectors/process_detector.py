"""Detect Autopsy process disappearance, abnormal exit, and Solr subprocess crash.

Covers crash types:
  1. Process Disappearance — the main Autopsy process terminates unexpectedly
  5. Solr Subprocess Crash — a critical child Java process dies while Autopsy lives
  7. Abnormal Exit — process exits with a non-zero return code
"""

from __future__ import annotations

import logging

import psutil

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.platform_utils import (
    get_case_lock_file,
    get_java_process_names,
)
from autopsyguard.platform_utils import get_global_lock_file
from autopsyguard.utils.process_utils import find_autopsy_pid

logger = logging.getLogger(__name__)


class ProcessDetector(BaseDetector):
    """Monitors the Autopsy process tree for disappearance and crashes."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__(config)
        # PID of the tracked Autopsy launcher process (set on first discovery)
        self._tracked_pid: int | None = None
        # PIDs of known child Java processes (includes Solr)
        self._tracked_children: set[int] = set()
        # Whether we already fired a "process disappeared" event
        self._process_lost_reported = False
        # Whether we already reported zombie state
        self._zombie_reported = False

    @property
    def name(self) -> str:
        return "ProcessDetector"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self) -> list[CrashEvent]:
        events: list[CrashEvent] = []

        if self._tracked_pid is None:
            # Try to discover the Autopsy process
            self._tracked_pid = find_autopsy_pid()
            if self._tracked_pid is not None:
                logger.debug("Tracking Autopsy PID %d", self._tracked_pid)
                self._process_lost_reported = False
                self._zombie_reported = False
                self._tracked_children = self._snapshot_children(self._tracked_pid)
            else:
                # Check for a stale lock file — suggests a crash happened
                # before we started monitoring
                events.extend(self._check_stale_lock())
            return events

        # We have a tracked PID — check if it's still alive
        if not psutil.pid_exists(self._tracked_pid):
            events.extend(self._handle_process_gone())
            return events

        try:
            proc = psutil.Process(self._tracked_pid)
            status = proc.status()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            events.extend(self._handle_process_gone())
            return events

        if status == psutil.STATUS_ZOMBIE:
            if not self._zombie_reported:
                events.append(CrashEvent(
                    crash_type=CrashType.ZOMBIE,
                    severity=Severity.CRITICAL,
                    message=f"Autopsy process (PID {self._tracked_pid}) is a zombie",
                    details={"pid": self._tracked_pid},
                ))
                self._zombie_reported = True
        else:
            # Process is not zombie - reset flag
            self._zombie_reported = False

        # Check for missing child processes (Solr crash)
        events.extend(self._check_children())

        return events

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _snapshot_children(self, pid: int) -> set[int]:
        """Snapshot current child PIDs of the Autopsy process.
        
        Args:
            pid: The parent Autopsy process PID to find children for.
            
        Returns:
            Set of child process PIDs that are Java processes (includes grandchildren).
            Empty set if parent doesn't exist or has no Java children.
            
        Note:
            Only includes children with names in get_java_process_names().
            Handles NoSuchProcess gracefully by returning empty set.
        """
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            java_names = [n.lower() for n in get_java_process_names()]
            java_children = {
                c.pid for c in children
                if c.name().lower() in java_names
            }
            if java_children:
                logger.info(
                    "Tracking %d Java child process(es): %s",
                    len(java_children),
                    java_children,
                )
            return java_children
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return set()

    def _handle_process_gone(self) -> list[CrashEvent]:
        """React to the main Autopsy process no longer being present."""
        events: list[CrashEvent] = []
        if not self._process_lost_reported:
            pid = self._tracked_pid

            # Try to get the exit code (may not be available)
            exit_code = self._get_exit_code(pid)
            details: dict = {"pid": pid}
            if exit_code is not None:
                details["exit_code"] = exit_code

            if exit_code is not None and exit_code != 0:
                events.append(CrashEvent(
                    crash_type=CrashType.ABNORMAL_EXIT,
                    severity=Severity.CRITICAL,
                    message=(
                        f"Autopsy (PID {pid}) exited with code {exit_code}"
                    ),
                    details=details,
                ))
            else:
                events.append(CrashEvent(
                    crash_type=CrashType.PROCESS_DISAPPEARED,
                    severity=Severity.CRITICAL,
                    message=f"Autopsy process (PID {pid}) has disappeared",
                    details=details,
                ))

            # Check for stale lock files (case-level or global)
            case_lock = get_case_lock_file(self.config.case_dir)
            global_lock = get_global_lock_file()
            if case_lock.exists():
                details["stale_lock_file"] = str(case_lock)
                logger.warning(
                    "Stale case lock file found at %s — confirms ungraceful shutdown",
                    case_lock,
                )
            elif global_lock.exists():
                details["stale_lock_file"] = str(global_lock)
                logger.warning(
                    "Global messages lock found at %s — corroborates ungraceful shutdown",
                    global_lock,
                )

            self._process_lost_reported = True

        # Reset tracking so we can pick up a restarted instance
        self._tracked_pid = None
        self._tracked_children.clear()
        return events

    def _check_children(self) -> list[CrashEvent]:
        """Detect if a previously-known child Java process has died."""
        if not self._tracked_children or self._tracked_pid is None:
            return []

        current_children = self._snapshot_children(self._tracked_pid)
        missing = self._tracked_children - current_children

        events: list[CrashEvent] = []
        for child_pid in missing:
            # Validate that the child was actually a child of our tracked process
            # Handle OS PID recycling by checking parent-child relationship
            is_valid_child = self._validate_child_relationship(child_pid, self._tracked_pid)
            
            if is_valid_child:
                events.append(CrashEvent(
                    crash_type=CrashType.SOLR_CRASH,
                    severity=Severity.WARNING,
                    message=(
                        f"Child Java process (PID {child_pid}) of Autopsy "
                        f"(PID {self._tracked_pid}) has disappeared — "
                        f"possible Solr or module subprocess crash"
                    ),
                    details={
                        "parent_pid": self._tracked_pid,
                        "child_pid": child_pid,
                    },
                ))
            else:
                logger.debug("Ignoring disappeared PID %d - was not a valid child of %d", 
                            child_pid, self._tracked_pid)

        # Update snapshot so we don't re-report
        self._tracked_children = current_children
        return events

    def _check_stale_lock(self) -> list[CrashEvent]:
        """If no Autopsy process is running but the lock file exists,
        a previous session likely crashed."""
        lock_file = get_case_lock_file(self.config.case_dir)
        if lock_file.exists():
            return [CrashEvent(
                crash_type=CrashType.PROCESS_DISAPPEARED,
                severity=Severity.WARNING,
                message=(
                    "No Autopsy process found but case lock file exists — "
                    "a previous session may have crashed"
                ),
                details={"stale_lock_file": str(lock_file)},
            )]
        return []

    @staticmethod
    def _get_exit_code(pid: int | None) -> int | None:
        """Try to retrieve the exit code of a terminated process.

        This is best-effort — on most systems the exit code is only
        available to the parent process.
        """
        if pid is None:
            return None
        try:
            proc = psutil.Process(pid)
            # If the process still exists as zombie, we can read the code
            return proc.wait(timeout=0)
        except (psutil.NoSuchProcess, psutil.TimeoutExpired, psutil.AccessDenied):
            return None

    def _validate_child_relationship(self, child_pid: int, parent_pid: int) -> bool:
        """Validate that a PID was actually a child of the parent process.
        
        This handles OS PID recycling where a PID might be reused for a different process.
        """
        try:
            # Check if the PID still exists
            if not psutil.pid_exists(child_pid):
                # Process is gone, so it was a legitimate child that died
                return True
                
            # Check if it's still a child of our parent
            child_proc = psutil.Process(child_pid)
            actual_parent_pid = child_proc.ppid()
            
            return actual_parent_pid == parent_pid
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process died or no access - assume it was a valid child
            return True
