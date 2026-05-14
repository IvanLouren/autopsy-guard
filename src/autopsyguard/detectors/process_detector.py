"""Detect Autopsy process disappearance, abnormal exit, and Solr subprocess crash.

Covers crash types:
  1. Process Disappearance — the main Autopsy process terminates unexpectedly
  5. Solr Subprocess Crash — a critical child Java process dies while Autopsy lives
  7. Abnormal Exit — process exits with a non-zero return code
"""

from __future__ import annotations

import logging
from pathlib import Path

import psutil

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.platform_utils import (
    get_case_lock_file,
    get_java_process_names,
    get_autopsy_process_names,
    get_global_lock_file,
)
from typing import Callable

from autopsyguard.utils.process_utils import find_autopsy_pid

logger = logging.getLogger(__name__)


class ProcessDetector(BaseDetector):
    """Monitors the Autopsy process tree for disappearance and crashes."""

    def __init__(self, config: MonitorConfig, *, _pid_finder: Callable[[], int | None] | None = None) -> None:
        super().__init__(config)
        # PID of the tracked Autopsy launcher process (set on first discovery)
        self._tracked_pid: int | None = None
        # PIDs of known child Java processes (includes Solr)
        self._tracked_children: set[int] = set()
        # Whether we already fired a "process disappeared" event
        self._process_lost_reported = False
        # Whether we already reported a stale lock while no process was running
        self._stale_lock_reported = False
        # Whether we already reported zombie state
        self._zombie_reported = False
        # PID finder function (injectable for tests). Default uses shared utility.
        self._pid_finder: Callable[[], int | None] = _pid_finder or find_autopsy_pid

    @property
    def name(self) -> str:
        return "ProcessDetector"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self) -> list[CrashEvent]:
        events: list[CrashEvent] = []
        if self._tracked_pid is None:
            # Try to discover the Autopsy process via the injected finder.
            # Default implementation delegates to the shared utility
            # `autopsyguard.utils.process_utils.find_autopsy_pid`.
            self._tracked_pid = self._pid_finder()
            if self._tracked_pid is not None:
                logger.debug("Tracking Autopsy PID %d", self._tracked_pid)
                self._process_lost_reported = False
                self._zombie_reported = False
                self._tracked_children = self._snapshot_children(self._tracked_pid)
                if self._tracked_children:
                    logger.info("Tracking %d Java child process(es): %s", len(self._tracked_children), self._tracked_children)
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
        """Snapshot current Java PIDs related to Autopsy/Solr.
        
        Args:
            pid: The parent Autopsy process PID to find children for.
            
        Returns:
            Set of Java process PIDs that should be tracked for disappearance:
            - Java descendants of the tracked Autopsy PID.
            - Solr-like Java processes discovered globally (Windows fallback).
            Empty set when none are discoverable.
            
        Note:
            Only includes children with names in get_java_process_names().
            Handles NoSuchProcess gracefully by returning empty set.
        """
        import time
        now = time.time()
        
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            java_names = [n.lower() for n in get_java_process_names()]
            if logger.isEnabledFor(logging.DEBUG):
                snapshot_rows: list[str] = []
                for c in children:
                    try:
                        age_s = now - float(c.create_time())
                    except Exception:
                        age_s = -1.0
                    try:
                        cmd = " ".join(c.cmdline())[:200]
                    except Exception:
                        cmd = "<unavailable>"
                    try:
                        ppid = c.ppid()
                    except Exception:
                        ppid = -1
                    try:
                        name = c.name()
                    except Exception:
                        name = "<unavailable>"
                    snapshot_rows.append(
                        f"pid={c.pid} ppid={ppid} name={name} age_s={age_s:.1f} cmd={cmd}"
                    )
                logger.debug(
                    "ProcessDetector child snapshot for parent PID %d: %d recursive children -> %s",
                    pid,
                    len(children),
                    snapshot_rows,
                )
            
            java_children = set()
            for c in children:
                if c.name().lower() in java_names:
                    # Ignore short-lived transient Java processes (e.g. wmic wrappers, version checks)
                    # Only track processes that have survived at least 15 seconds
                    try:
                        if (now - float(c.create_time())) >= 15.0:
                            java_children.add(c.pid)
                    except Exception:
                        pass
                        
            # Windows/process-chain fallback:
            # Solr may be launched outside the tracked Autopsy process tree.
            solr_global = self._snapshot_global_solr_java_pids(now=now)
            combined = java_children | solr_global
            logger.debug(
                "ProcessDetector combined Java snapshot for parent PID %d: tree=%s global_solr=%s combined=%s",
                pid,
                sorted(java_children),
                sorted(solr_global),
                sorted(combined),
            )
            return combined
        except Exception:
            logger.debug("ProcessDetector child snapshot failed for parent PID %d", pid, exc_info=True)
            return set()

    def _snapshot_global_solr_java_pids(self, *, now: float | None = None) -> set[int]:
        """Find Solr JVMs even when they are not parented under Autopsy.

        This is primarily for Windows where launcher/wrapper chains can break
        parent-child visibility from the tracked Autopsy PID.
        """
        if now is None:
            import time
            now = time.time()

        java_names = {n.lower() for n in get_java_process_names()}
        solr_pids: set[int] = set()

        for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time", "exe"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmdline = proc.info.get("cmdline") or []
                exe = proc.info.get("exe")
                create_time = float(proc.info.get("create_time") or 0.0)
                age_s = now - create_time if create_time > 0 else 0.0

                # Determine whether this process is a JVM.
                is_java = False
                if name in java_names:
                    is_java = True
                elif cmdline:
                    first = Path(str(cmdline[0])).name.lower()
                    if first in java_names:
                        is_java = True
                if not is_java and exe:
                    try:
                        if Path(str(exe)).name.lower() in java_names:
                            is_java = True
                    except Exception:
                        pass
                if not is_java:
                    continue

                if self._looks_like_solr_java_cmdline(cmdline):
                    # Solr signature match is trusted: do not enforce 15s age gate.
                    solr_pids.add(proc.info["pid"])
                elif age_s >= 15.0:
                    # Keep legacy age guard for generic Java candidates.
                    # We only include these if command-line inspection was unavailable.
                    try:
                        if not cmdline and self._looks_like_solr_java_cmdline(proc.cmdline()):
                            solr_pids.add(proc.info["pid"])
                    except Exception:
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        return solr_pids

    def _looks_like_solr_java_cmdline(self, cmdline: list[object]) -> bool:
        """Best-effort Solr JVM matcher based on Java command-line markers."""
        if not cmdline:
            return False
        cmd = " ".join(str(x).lower() for x in cmdline)
        port_token = f":{self.config.solr_port}"
        markers = (
            "solr",
            "start.jar",
            "org.apache.solr",
            "-dsolr.",
            "solr.port",
        )
        if any(m in cmd for m in markers):
            return True
        return port_token in cmd

    # NOTE: PID discovery is delegated to an injectable finder (`self._pid_finder`).
    # The previous implementation attempted to detect test mocks at runtime
    # which is not appropriate for production code. Tests should inject a
    # custom finder when they need to control discovery.

    def _handle_process_gone(self) -> list[CrashEvent]:
        """React to the main Autopsy process no longer being present."""
        events: list[CrashEvent] = []
        
        # Before assuming a crash, check if another Autopsy process exists.
        # Autopsy uses a transient launcher that spawns the real app and exits.
        new_pid = self._pid_finder()
        if new_pid is not None and new_pid != self._tracked_pid:
            logger.info("Autopsy process tracking switched from launcher PID %s to real app PID %s", 
                        self._tracked_pid, new_pid)
            self._tracked_pid = new_pid
            self._tracked_children = self._snapshot_children(self._tracked_pid)
            return events

        if not self._process_lost_reported:
            pid = self._tracked_pid

            # Try to get the exit code (may not be available)
            exit_code = self._get_exit_code(pid)
            details: dict = {"pid": pid}
            if exit_code is not None:
                details["exit_code"] = exit_code

            # Check for stale lock files (case-level or global)
            case_lock = get_case_lock_file(self.config.case_dir)
            global_lock = get_global_lock_file()
            locks_exist = case_lock.exists() or global_lock.exists()

            # If no locks remain and exit code is 0 (or unknown), it's a graceful shutdown
            if not locks_exist and (exit_code == 0 or exit_code is None):
                logger.info("Autopsy process exited gracefully (no locks remaining).")
            else:
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
        logger.debug(
            "ProcessDetector child diff for parent PID %d: tracked=%s current=%s missing=%s",
            self._tracked_pid,
            sorted(self._tracked_children),
            sorted(current_children),
            sorted(missing),
        )

        events: list[CrashEvent] = []
        for child_pid in missing:
            # Decide whether this missing PID should be treated as a real
            # disappeared child event (vs still alive under current parent).
            should_report_missing_child = self._should_report_missing_child(
                child_pid, self._tracked_pid
            )

            if should_report_missing_child:
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
                logger.debug(
                    "Skipping missing child PID %d - still appears attached to parent %d",
                    child_pid,
                    self._tracked_pid,
                )

        # Update snapshot so we don't re-report
        new_tracked = current_children - self._tracked_children
        if new_tracked:
            logger.info("Tracking %d NEW Java child process(es): %s", len(new_tracked), new_tracked)
            
        self._tracked_children = current_children
        return events

    def _check_stale_lock(self) -> list[CrashEvent]:
        """If no Autopsy process is running but the lock file exists,
        a previous session likely crashed."""
        lock_file = get_case_lock_file(self.config.case_dir)
        if lock_file.exists():
            if self._stale_lock_reported:
                return []
            self._stale_lock_reported = True
            return [CrashEvent(
                crash_type=CrashType.PROCESS_DISAPPEARED,
                severity=Severity.WARNING,
                message=(
                    "No Autopsy process found but case lock file exists — "
                    "a previous session may have crashed"
                ),
                details={"stale_lock_file": str(lock_file)},
            )]
        # Lock was cleaned up — allow re-reporting if it returns later.
        self._stale_lock_reported = False
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

    def _should_report_missing_child(self, child_pid: int, parent_pid: int) -> bool:
        """Return True when a missing PID should be reported as disappeared.

        Semantics:
        - True  -> child looks genuinely missing/recycled/inaccessible, report it.
        - False -> child still appears attached to the tracked parent, suppress.
        """
        # Conservative by design: if process inspection fails, prefer reporting
        # potential Solr child crashes rather than silently missing them.
        if not psutil.pid_exists(child_pid):
            return True

        # If parent still lists this PID as a child, suppress this "missing"
        # event (it is likely a transient snapshot mismatch).
        try:
            parent_proc = psutil.Process(parent_pid)
            parent_children = {c.pid for c in parent_proc.children(recursive=True)}
            if child_pid in parent_children:
                return False
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Fall through to child-side parent check below.
            pass

        # Parent does not list this PID anymore, or parent inspection failed.
        # Check child->parent relation when possible to avoid PID reuse false
        # positives.
        try:
            child_proc = psutil.Process(child_pid)
            actual_parent_pid = child_proc.ppid()
            return actual_parent_pid != parent_pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return True
