"""Detect Solr service crashes, hangs, and health issues.

Covers crash types:
  - Solr Subprocess Crash (via HTTP Health Checks)
  - Solr Hang (slow query responses indicating frozen/overloaded state)
"""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity

logger = logging.getLogger(__name__)

# Solr port used by Autopsy's embedded instance
SOLR_PORT = 23232
SOLR_BASE_URL = f"http://localhost:{SOLR_PORT}"

# Thresholds for hang detection
SOLR_TIMEOUT_SECONDS = 5.0  # Request timeout
SOLR_SLOW_THRESHOLD_SECONDS = 2.0  # Responses slower than this are "slow"
SOLR_SLOW_COUNT_THRESHOLD = 3  # Consecutive slow responses = hang


class SolrDetector(BaseDetector):
    """Monitors the local Solr service via its HTTP REST API.
    
    Detects two conditions:
      1. Solr DOWN — service not responding at all (crash/dead)
      2. Solr HANG — service responding but very slowly (frozen/overloaded)
    """

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__(config)
        self._solr_down_reported = False
        self._solr_hang_reported = False
        self._consecutive_slow_responses = 0

    @property
    def name(self) -> str:
        return "SolrDetector"

    def check(self) -> list[CrashEvent]:
        events: list[CrashEvent] = []

        # Health check endpoint (JSON format)
        solr_url = f"{SOLR_BASE_URL}/solr/admin/info/system?wt=json"
        
        start_time = time.time()
        try:
            response = urllib.request.urlopen(solr_url, timeout=SOLR_TIMEOUT_SECONDS)
            body = response.read().decode('utf-8')
            elapsed = time.time() - start_time
            
            if response.status == 200:
                # Solr is alive — check if it was previously down
                if self._solr_down_reported:
                    logger.info("Solr service has recovered and is responding on port %d.", SOLR_PORT)
                self._solr_down_reported = False
                
                # Check for slow response (potential hang)
                events.extend(self._check_slow_response(elapsed))
                
                # Parse Hardware Metrics
                try:
                    data = json.loads(body)
                    events.extend(self._check_hardware_metrics(data))
                except json.JSONDecodeError:
                    logger.warning("Failed to parse JSON from Solr APIs")
                
        except urllib.error.URLError as e:
            # Timeout is a URLError with a socket.timeout reason
            elapsed = time.time() - start_time
            if self._is_timeout_error(e):
                events.extend(self._handle_timeout(elapsed))
            else:
                events.extend(self._handle_connection_error(e, solr_url))
                
        except ConnectionError as e:
            events.extend(self._handle_connection_error(e, solr_url))

        return events

    def _check_hardware_metrics(self, data: dict) -> list[CrashEvent]:
        """Extract CPU and RAM usage from the Solr JSON payload."""
        events: list[CrashEvent] = []
        try:
            # systemCpuLoad is 0.0 to 1.0
            cpu_percent = data.get("system", {}).get("systemCpuLoad", 0.0) * 100.0
            
            # JVM RAM used percent
            ram_percent = data.get("jvm", {}).get("memory", {}).get("raw", {}).get("used%", 0.0)
            
            if cpu_percent > self.config.cpu_warning_percent:
                events.append(CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.WARNING,
                    message=f"Solr is using excessive CPU: {cpu_percent:.1f}%",
                    details={"cpu_percent": cpu_percent}
                ))
                
            if ram_percent > self.config.memory_warning_percent:
                events.append(CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.WARNING,
                    message=f"Solr JVM Heap is dangerously full: {ram_percent:.1f}%",
                    details={"ram_percent": ram_percent}
                ))
        except Exception as e:
            logger.debug("Failed to extract specific metrics from Solr JSON: %s", e)
            
        return events

    def _check_slow_response(self, elapsed: float) -> list[CrashEvent]:
        """Detect Solr hang via consistently slow responses."""
        events: list[CrashEvent] = []
        
        if elapsed >= SOLR_SLOW_THRESHOLD_SECONDS:
            self._consecutive_slow_responses += 1
            logger.debug(
                "Solr slow response: %.2fs (consecutive: %d)",
                elapsed, self._consecutive_slow_responses
            )
            
            if (self._consecutive_slow_responses >= SOLR_SLOW_COUNT_THRESHOLD
                    and not self._solr_hang_reported):
                events.append(CrashEvent(
                    crash_type=CrashType.HANG,
                    severity=Severity.WARNING,
                    message=(
                        f"Solr appears hung — {self._consecutive_slow_responses} consecutive "
                        f"slow responses (>{SOLR_SLOW_THRESHOLD_SECONDS}s each)"
                    ),
                    details={
                        "last_response_time": elapsed,
                        "consecutive_slow_count": self._consecutive_slow_responses,
                        "threshold_seconds": SOLR_SLOW_THRESHOLD_SECONDS,
                    },
                ))
                self._solr_hang_reported = True
        else:
            # Fast response — reset counters
            if self._solr_hang_reported:
                logger.info("Solr response times have normalized (%.2fs).", elapsed)
            self._consecutive_slow_responses = 0
            self._solr_hang_reported = False
            
        return events

    def _handle_timeout(self, elapsed: float) -> list[CrashEvent]:
        """Handle request timeout — severe form of hang."""
        events: list[CrashEvent] = []
        self._consecutive_slow_responses += 1
        
        if not self._solr_hang_reported:
            events.append(CrashEvent(
                crash_type=CrashType.HANG,
                severity=Severity.CRITICAL,
                message=(
                    f"Solr request timed out after {elapsed:.1f}s — "
                    f"service may be frozen"
                ),
                details={
                    "timeout_seconds": SOLR_TIMEOUT_SECONDS,
                    "elapsed": elapsed,
                },
            ))
            self._solr_hang_reported = True
            
        return events

    def _handle_connection_error(self, error: Exception, url: str) -> list[CrashEvent]:
        """Handle connection refused or other network errors."""
        events: list[CrashEvent] = []
        
        if not self._solr_down_reported:
            events.append(CrashEvent(
                crash_type=CrashType.SOLR_CRASH,
                severity=Severity.CRITICAL,
                message=f"Solr service not responding on port {SOLR_PORT}",
                details={"error": str(error), "url": url},
            ))
            self._solr_down_reported = True
            
        # Reset hang tracking since service is down, not hung
        self._consecutive_slow_responses = 0
        self._solr_hang_reported = False
        
        return events

    @staticmethod
    def _is_timeout_error(error: urllib.error.URLError) -> bool:
        """Check if URLError was caused by a timeout."""
        import socket
        reason = getattr(error, 'reason', None)
        if isinstance(reason, socket.timeout):
            return True
        if isinstance(reason, TimeoutError):
            return True
        # Some systems wrap it differently
        return "timed out" in str(error).lower()
