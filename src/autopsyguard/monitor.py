"""Main monitoring loop that orchestrates all detectors.

The monitor operates in three states:
  WAITING  — Autopsy is not running or the case is not active; detectors are idle.
  ACTIVE   — Autopsy is running with an active case; detectors are polling.
  FINISHED — Autopsy shut down gracefully (lock file removed); monitoring stops.

This ensures we only monitor during actual ingest/processing, not on idle case dirs.
"""

from __future__ import annotations

import enum
import logging
import time

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.detectors.hang_detector import HangDetector
from autopsyguard.detectors.jvm_crash_detector import JvmCrashDetector
from autopsyguard.detectors.log_detector import LogDetector
from autopsyguard.detectors.process_detector import ProcessDetector
from autopsyguard.detectors.resource_detector import ResourceDetector
from autopsyguard.detectors.solr_detector import SolrDetector
from autopsyguard.models import CrashEvent
from autopsyguard.platform_utils import (
    find_autopsy_process,
    get_case_lock_file,
)

logger = logging.getLogger(__name__)


class MonitorState(enum.Enum):
    WAITING = "waiting"
    ACTIVE = "active"
    FINISHED = "finished"


class Monitor:
    """Runs all detectors in a polling loop and collects events.

    Only activates detectors when Autopsy is running AND the case is open
    (lock file present).  This prevents false positives on idle case dirs.
    """

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self.detectors: list[BaseDetector] = [
            ProcessDetector(config),
            JvmCrashDetector(config),
            LogDetector(config),
            HangDetector(config),
            ResourceDetector(config),
            SolrDetector(config),
        ]
        self._running = False
        self._state = MonitorState.WAITING

    def _is_case_active(self) -> bool:
        """Check if Autopsy is running and the case is open."""
        pid = find_autopsy_process()
        lock_exists = get_case_lock_file(self.config.case_dir).exists()
        return pid is not None and lock_exists

    def run_once(self) -> list[CrashEvent]:
        """Execute a single detection cycle across all detectors."""
        events: list[CrashEvent] = []
        for detector in self.detectors:
            try:
                new_events = detector.check()
                events.extend(new_events)
            except Exception:
                logger.exception("Error in detector %s", detector.name)
        return events

    def run(self) -> None:
        """Start the continuous monitoring loop.

        Waits for Autopsy + active case before running detectors.
        Distinguishes graceful shutdown from crashes.
        """
        self._running = True
        self._state = MonitorState.WAITING
        logger.info(
            "AutopsyGuard starting — monitoring case at %s (poll every %.1fs)",
            self.config.case_dir,
            self.config.poll_interval,
        )

        try:
            while self._running:
                if self._state == MonitorState.WAITING:
                    self._handle_waiting()
                elif self._state == MonitorState.ACTIVE:
                    self._handle_active()
                elif self._state == MonitorState.FINISHED:
                    break

                time.sleep(self.config.poll_interval)

        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        finally:
            self._running = False
            logger.info("AutopsyGuard stopped (state: %s)", self._state.value)

    def stop(self) -> None:
        """Signal the monitoring loop to stop."""
        self._running = False

    def _handle_waiting(self) -> None:
        """Wait until Autopsy is running and the case is active."""
        if self._is_case_active():
            self._state = MonitorState.ACTIVE
            logger.info(
                "Autopsy is running and case is active — starting detection"
            )
        else:
            pid = find_autopsy_process()
            lock = get_case_lock_file(self.config.case_dir).exists()
            logger.debug(
                "Waiting for Autopsy (process: %s, lock file: %s)",
                pid if pid else "not found",
                "present" if lock else "absent",
            )

    def _handle_active(self) -> None:
        """Run detectors while the case is being processed."""
        events = self.run_once()
        for event in events:
            self._handle_event(event)

        # Check if Autopsy shut down gracefully (process gone + lock removed)
        pid = find_autopsy_process()
        lock_exists = get_case_lock_file(self.config.case_dir).exists()

        if pid is None and not lock_exists:
            # Graceful shutdown: process exited and lock file was cleaned up
            self._state = MonitorState.FINISHED
            logger.info(
                "Autopsy shut down gracefully — case processing complete"
            )
        elif pid is None and lock_exists:
            # Process gone but lock file remains — crash already detected
            # by ProcessDetector; stay active in case Autopsy restarts
            pass

    @staticmethod
    def _handle_event(event: CrashEvent) -> None:
        """Log a detected event.  Future: send email / webhook / etc."""
        logger.warning("EVENT DETECTED: %s", event)
