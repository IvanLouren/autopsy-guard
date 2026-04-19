"""Detect Solr service crashes, hangs, and health issues.

Covers crash types:
  - Solr Subprocess Crash (via HTTP Health Checks)
  - Solr Hang (slow query responses indicating frozen/overloaded state)
  - Resource Issues (high CPU, memory, GC pressure via Metrics API)
  - Indexing Errors (via Core status API)
  - Log Errors (via Solr log file monitoring)
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from itertools import chain

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.platform_utils import get_autopsy_user_dir, get_autopsyguard_state_dir
from autopsyguard.utils.log_tracker import LogFileTracker

logger = logging.getLogger(__name__)


@dataclass
class SolrMetrics:
    """Parsed Solr metrics from the admin API."""
    heap_used_mb: float = 0.0
    heap_max_mb: float = 0.0
    heap_usage_percent: float = 0.0
    cpu_percent: float = 0.0
    thread_count: int = 0
    gc_count: int = 0
    gc_time_ms: int = 0


def get_solr_log_dir() -> Path:
    """Return the Solr log directory for Autopsy's embedded instance.

    Autopsy stores Solr logs in the var/log/solr directory.
    """
    # In Autopsy 4.22.x the Solr logs are placed directly in the global
    # Autopsy log directory (var/log), not in a `solr/` subdirectory.
    return get_autopsy_log_dir()


class SolrDetector(BaseDetector):
    """Monitors the local Solr service via its HTTP REST API and logs.

    Detects multiple conditions:
      1. Solr DOWN — service not responding at all (crash/dead)
      2. Solr HANG — service responding but very slowly (frozen/overloaded)
      3. Resource Issues — high heap usage, CPU, or GC pressure
      4. Core Errors — indexing failures or corrupt cores
      5. Log Errors — errors detected in Solr log files
    """

    def __init__(self, config: MonitorConfig, solr_cache=None) -> None:
        super().__init__(config)
        self._solr_cache = solr_cache
        self._solr_down_reported = False
        self._solr_hang_reported = False
        self._consecutive_slow_responses = 0
        self._heap_warning_reported = False
        self._cpu_warning_reported = False
        self._reported_log_errors: set[str] = set()
        self._initialized = False
        
        # Initialize log file tracker with persistence (stored outside case)
        state_dir = get_autopsyguard_state_dir(config.case_dir)
        state_file = state_dir / "solr_log_positions.json"
        self._log_tracker = LogFileTracker(state_file=state_file)
        self._log_tracker.load_positions()

    @property
    def name(self) -> str:
        return "SolrDetector"

    def check(self) -> list[CrashEvent]:
        events: list[CrashEvent] = []
        # Use shared solr cache if available for the health probe
        elapsed: float | None = None
        try:
            if self._solr_cache is not None:
                status = self._solr_cache.get_status()
                if status.is_up:
                    elapsed = status.response_time or 0.0
                    if self._solr_down_reported:
                        logger.info(
                            "Solr service has recovered and is responding on port %d.",
                            self.config.solr_port,
                        )
                    self._solr_down_reported = False
                else:
                    # Treat as connection error
                    return self._handle_connection_error(Exception(status.error or "solr down"), f"{self._solr_base_url}/solr/admin/info/system")

        except Exception:
            # If cache fails, fall back to original direct probe below
            elapsed = None

        # If cached elapsed is available, use it for slow-check; otherwise do direct probe
        if elapsed is None:
            # Discover a core and perform a lightweight ping for liveness
            cores_url = f"{self._solr_base_url}/solr/admin/cores?action=STATUS&wt=json"
            start_time = time.time()
            try:
                with urllib.request.urlopen(cores_url, timeout=self.config.solr_timeout_seconds) as cresp:
                    import json
                    parsed = json.loads(cresp.read())
                    cores = list(parsed.get("status", {}).keys())
                    if not cores:
                        raise ValueError("no cores")
                    core = cores[0]
                    ping_url = f"{self._solr_base_url}/solr/{core}/admin/ping?wt=json"
                    start_ping = time.time()
                    with urllib.request.urlopen(ping_url, timeout=self.config.solr_timeout_seconds) as presp:
                        elapsed = time.time() - start_ping
                        if presp.status == 200:
                            if self._solr_down_reported:
                                logger.info(
                                    "Solr service has recovered and is responding on port %d.",
                                    self.config.solr_port,
                                )
                            self._solr_down_reported = False
            except urllib.error.URLError as e:
                elapsed = time.time() - start_time
                if self._is_timeout_error(e):
                    events.extend(self._handle_timeout(elapsed))
                else:
                    # Use a generic ping-ish URL for reporting if cores discovery failed
                    events.extend(self._handle_connection_error(e, f"{self._solr_base_url}/solr/admin/ping"))
                events.extend(self._check_logs())
                return events
            except Exception as e:
                events.extend(self._handle_connection_error(e, f"{self._solr_base_url}/solr/admin/ping"))
                events.extend(self._check_logs())
                return events

        # Check for slow response (potential hang)
        if elapsed is not None:
            events.extend(self._check_slow_response(elapsed))

        # Now that Solr is responsive, check metrics and cores
        events.extend(self._check_metrics())
        events.extend(self._check_cores())

        # Always check logs (even if Solr is down, logs may have info)
        events.extend(self._check_logs())

        return events

    def _check_slow_response(self, elapsed: float) -> list[CrashEvent]:
        """Detect Solr hang via consistently slow responses."""
        events: list[CrashEvent] = []
        
        if elapsed >= self.config.solr_slow_threshold_seconds:
            self._consecutive_slow_responses += 1
            logger.debug(
                "Solr slow response: %.2fs (consecutive: %d)",
                elapsed, self._consecutive_slow_responses
            )
            
            if (self._consecutive_slow_responses >= self.config.solr_slow_count_threshold
                    and not self._solr_hang_reported):
                events.append(CrashEvent(
                    crash_type=CrashType.HANG,
                    severity=Severity.WARNING,
                    message=(
                        f"Solr appears hung — {self._consecutive_slow_responses} consecutive "
                        f"slow responses (>{self.config.solr_slow_threshold_seconds}s each)"
                    ),
                    details={
                        "last_response_time": elapsed,
                        "consecutive_slow_count": self._consecutive_slow_responses,
                        "threshold_seconds": self.config.solr_slow_threshold_seconds,
                    },
                ))
                self._solr_hang_reported = True
        else:
            # Fast response — reset counters and clear hang flag
            if self._consecutive_slow_responses > 0 or self._solr_hang_reported:
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
                    "timeout_seconds": self.config.solr_timeout_seconds,
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
                message=f"Solr service not responding on port {self.config.solr_port}",
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

    def _check_metrics(self) -> list[CrashEvent]:
        """Fetch and analyze Solr metrics for resource issues."""
        events: list[CrashEvent] = []
        metrics = self._fetch_metrics()
        if metrics is None:
            return events

        # Check heap usage
        if metrics.heap_usage_percent >= self.config.solr_heap_usage_critical:
            if not self._heap_warning_reported:
                events.append(CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.CRITICAL,
                    message=(
                        f"Solr heap usage critical: {metrics.heap_usage_percent:.1f}% "
                        f"({metrics.heap_used_mb:.0f}MB/{metrics.heap_max_mb:.0f}MB)"
                    ),
                    details={
                        "heap_used_mb": metrics.heap_used_mb,
                        "heap_max_mb": metrics.heap_max_mb,
                        "heap_usage_percent": metrics.heap_usage_percent,
                        "cpu_percent": metrics.cpu_percent,
                        "thread_count": metrics.thread_count,
                        "gc_count": metrics.gc_count,
                        "gc_time_ms": metrics.gc_time_ms,
                    },
                ))
                self._heap_warning_reported = True
        elif metrics.heap_usage_percent >= self.config.solr_heap_usage_warning:
            if not self._heap_warning_reported:
                events.append(CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.WARNING,
                    message=(
                        f"Solr heap usage high: {metrics.heap_usage_percent:.1f}% "
                        f"({metrics.heap_used_mb:.0f}MB/{metrics.heap_max_mb:.0f}MB)"
                    ),
                    details={
                        "heap_used_mb": metrics.heap_used_mb,
                        "heap_max_mb": metrics.heap_max_mb,
                        "heap_usage_percent": metrics.heap_usage_percent,
                    },
                ))
                self._heap_warning_reported = True
        else:
            if self._heap_warning_reported:
                logger.info(
                    "Solr heap usage normalized: %.1f%%", metrics.heap_usage_percent
                )
            self._heap_warning_reported = False

        # Check CPU usage
        if metrics.cpu_percent >= self.config.solr_cpu_warning:
            if not self._cpu_warning_reported:
                events.append(CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.WARNING,
                    message=f"Solr CPU usage high: {metrics.cpu_percent:.1f}%",
                    details={
                        "cpu_percent": metrics.cpu_percent,
                        "thread_count": metrics.thread_count,
                    },
                ))
                self._cpu_warning_reported = True
        else:
            if self._cpu_warning_reported:
                logger.info("Solr CPU usage normalized: %.1f%%", metrics.cpu_percent)
            self._cpu_warning_reported = False

        return events

    def _fetch_metrics(self) -> SolrMetrics | None:
        """Fetch metrics from Solr's admin API.

        Uses /solr/admin/metrics to get JVM memory, CPU, threads, and GC stats.
        """
        metrics_url = f"{self._solr_base_url}/solr/admin/metrics?group=jvm&wt=json"
        try:
            with urllib.request.urlopen(metrics_url, timeout=self.config.solr_timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
            return self._parse_metrics(data)
        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
            logger.debug("Failed to fetch Solr metrics: %s", e)
            return None

    def _parse_metrics(self, data: dict) -> SolrMetrics | None:
        """Parse Solr metrics JSON response into SolrMetrics dataclass.
        
        Returns None if parsing fails to allow caller to handle the error.
        """
        metrics = SolrMetrics()
        try:
            jvm_metrics = data.get("metrics", {}).get("solr.jvm", {})

            # Memory metrics
            memory = jvm_metrics.get("memory.heap.used", 0)
            memory_max = jvm_metrics.get("memory.heap.max", 0)

            # Handle different response formats (value objects vs direct values)
            if isinstance(memory, dict):
                memory = memory.get("value", 0)
            if isinstance(memory_max, dict):
                memory_max = memory_max.get("value", 0)

            metrics.heap_used_mb = memory / (1024 * 1024) if memory else 0
            metrics.heap_max_mb = memory_max / (1024 * 1024) if memory_max else 0
            if metrics.heap_max_mb > 0:
                metrics.heap_usage_percent = (
                    metrics.heap_used_mb / metrics.heap_max_mb
                ) * 100

            # CPU metrics (process CPU load)
            cpu_load = jvm_metrics.get("os.processCpuLoad", 0)
            if isinstance(cpu_load, dict):
                cpu_load = cpu_load.get("value", 0)
            metrics.cpu_percent = cpu_load * 100 if cpu_load else 0

            # Thread metrics
            threads = jvm_metrics.get("threads.count", 0)
            if isinstance(threads, dict):
                threads = threads.get("value", 0)
            metrics.thread_count = int(threads) if threads else 0

            # GC metrics (try to find any GC collector)
            for key, value in jvm_metrics.items():
                if "gc." in key and ".count" in key:
                    if isinstance(value, dict):
                        value = value.get("value", 0)
                    metrics.gc_count += int(value) if value else 0
                elif "gc." in key and ".time" in key:
                    if isinstance(value, dict):
                        value = value.get("value", 0)
                    metrics.gc_time_ms += int(value) if value else 0

            return metrics

        except (KeyError, TypeError, ValueError) as e:
            logger.debug("Error parsing Solr metrics: %s", e)
            return None

    def _check_cores(self) -> list[CrashEvent]:
        """Check Solr core status for errors or issues."""
        events: list[CrashEvent] = []
        cores_url = f"{self._solr_base_url}/solr/admin/cores?action=STATUS&wt=json"

        try:
            with urllib.request.urlopen(cores_url, timeout=self.config.solr_timeout_seconds) as response:
                data = json.loads(response.read().decode("utf-8"))
            status = data.get("status", {})

            for core_name, core_info in status.items():
                # Check for index errors
                index_info = core_info.get("index", {})
                has_deletions = index_info.get("hasDeletions", False)
                num_docs = index_info.get("numDocs", 0)
                size_bytes = index_info.get("sizeInBytes", 0)

                # Check for initialization failures
                init_failures = data.get("initFailures", {})
                if core_name in init_failures:
                    error_key = f"core_init_{core_name}"
                    if error_key not in self._reported_log_errors:
                        events.append(CrashEvent(
                            crash_type=CrashType.SOLR_CRASH,
                            severity=Severity.CRITICAL,
                            message=f"Solr core '{core_name}' failed to initialize",
                            details={
                                "core_name": core_name,
                                "error": init_failures[core_name],
                            },
                        ))
                        self._reported_log_errors.add(error_key)

        except (urllib.error.URLError, json.JSONDecodeError) as e:
            logger.debug("Failed to fetch Solr core status: %s", e)

        return events

    def _check_logs(self) -> list[CrashEvent]:
        """Monitor Solr log files for errors."""
        events: list[CrashEvent] = []
        log_dir = get_solr_log_dir()

        if not log_dir.exists():
            logger.debug("Solr log directory does not exist: %s", log_dir)
            return events

        # Check the main solr.log file
        log_patterns = [
            (re.compile(r"ERROR", re.IGNORECASE), Severity.CRITICAL),
            (re.compile(r"SEVERE", re.IGNORECASE), Severity.CRITICAL),
            (re.compile(r"OutOfMemoryError", re.IGNORECASE), Severity.CRITICAL),
            (re.compile(r"WARN.*(?:corrupt|failed|exception)", re.IGNORECASE), Severity.WARNING),
        ]

        for log_file in chain(log_dir.glob("solr*.log"), log_dir.glob("solr*.log.*")):
            try:
                # On first run, seek to end to ignore pre-existing errors
                if not self._initialized and self._log_tracker.get_position(log_file) == 0:
                    # Set position to end of file on first run
                    if log_file.exists():
                        self._log_tracker._file_offsets[log_file] = log_file.stat().st_size
                    continue
                events.extend(self._scan_log_file(log_file, log_patterns))
            except OSError as e:
                logger.debug("Failed to read Solr log %s: %s", log_file, e)

        if not self._initialized:
            self._initialized = True
            tracked_count = len(self._log_tracker._file_offsets)
            logger.debug("SolrDetector: tracking %d Solr log file(s)", tracked_count)
            # Save initial positions
            self._log_tracker.save_positions()

        return events

    def _scan_log_file(
        self,
        log_file: Path,
        patterns: list[tuple[re.Pattern, Severity]],
    ) -> list[CrashEvent]:
        """Scan a single log file for error patterns."""
        events: list[CrashEvent] = []

        # Use LogFileTracker for incremental reading
        new_content = self._log_tracker.read_new_content(log_file)
        
        if not new_content:
            return events

        # Track which errors we've already reported in THIS batch to avoid
        # reporting the same stack trace multiple times when ERROR appears
        # on multiple consecutive lines
        batch_reported = set()

        # Scan line by line for error patterns
        for line in new_content.splitlines():
            if not line.strip():  # Skip empty lines
                continue
                
            for pattern, severity in patterns:
                if pattern.search(line):
                    # Create unique key using stable hash to survive process restarts
                    # Use first 100 chars of the line for deduplication
                    line_hash = hashlib.md5(line[:100].encode('utf-8')).hexdigest()[:16]
                    error_key = f"{log_file.name}:{line_hash}"
                    
                    # Skip if already reported (persistent) or in current batch
                    if error_key not in self._reported_log_errors and error_key not in batch_reported:
                        # For stack traces: only report the first line (the one with timestamp)
                        # Stack trace continuation lines typically start with whitespace or "Caused by:"
                        if line[0].isspace() or line.strip().startswith("Caused by:") or line.strip().startswith("=>"):
                            # This is a continuation line, skip it
                            break
                        
                        events.append(CrashEvent(
                            crash_type=CrashType.LOG_ERROR,
                            severity=severity,
                            message=f"Solr log error in {log_file.name}",
                            details={
                                "log_file": str(log_file),
                                "log_line": line[:500],  # Truncate long lines
                            },
                        ))
                        self._reported_log_errors.add(error_key)
                        batch_reported.add(error_key)
                        # Limit to first matching pattern per line
                        break

        # Save positions after processing
        if events:
            self._log_tracker.save_positions()

        return events

    def get_current_metrics(self) -> SolrMetrics | None:
        """Public method to get current Solr metrics.

        Useful for reporting/dashboard purposes.
        """
        return self._fetch_metrics()

    @property
    def _solr_base_url(self) -> str:
        return f"http://localhost:{self.config.solr_port}"

