"""Shared Solr health probe with short-lived caching.

Detectors that need to check Solr liveness/latency should consult a
single shared `SolrHealthCache` to avoid duplicate HTTP probes each
monitoring cycle.
"""
from __future__ import annotations

import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional

from autopsyguard.config import MonitorConfig


@dataclass
class SolrStatus:
    is_up: bool
    response_time: Optional[float]
    checked_at: float
    error: Optional[str] = None


class SolrHealthCache:
    _DOWN_CIRCUIT_THRESHOLD = 6
    _DOWN_CIRCUIT_PROBE_INTERVAL_MULTIPLIER = 5.0
    _DOWN_CIRCUIT_MIN_INTERVAL_SECONDS = 30.0

    def __init__(self, config: MonitorConfig) -> None:
        self._config = config
        self._status: Optional[SolrStatus] = None
        # Track recent reports emitted by detectors to enable cooperation
        # between Solr-related detectors (avoid duplicate alerts).
        self._last_reported: dict[str, float] = {}
        # Circuit breaker: track consecutive down checks and when to resume probing
        self._consecutive_down_checks = 0
        self._circuit_open_until_monotonic = 0.0

    def mark_report(self, kind: str) -> None:
        """Record that a detector has reported a given condition (e.g. 'hang'|'down')."""
        self._last_reported[kind] = time.time()

    def was_reported_recently(self, kind: str, within_seconds: float) -> bool:
        """Return True if `kind` was reported within the last `within_seconds` seconds."""
        ts = self._last_reported.get(kind)
        if ts is None:
            return False
        return (time.time() - ts) < within_seconds

    def _probe(self) -> SolrStatus:
        # Lightweight liveness check: use the cores API as the primary
        # signal and avoid /admin/ping because some Autopsy/Solr setups
        # delegate ping to a missing request handler (qt=search), which
        # produces noisy non-fatal HTTP 400 log spam.
        cores_url = f"http://localhost:{self._config.solr_port}/solr/admin/cores?action=STATUS&wt=json"
        try:
            start = time.time()
            with urllib.request.urlopen(cores_url, timeout=self._config.solr_timeout_seconds) as resp:
                elapsed = time.time() - start
                data = resp.read()
                # Validate body is JSON-like enough to avoid treating
                # malformed responses as healthy.
                import json
                if isinstance(data, bytes):
                    parsed = json.loads(data)
                else:
                    parsed = json.loads(str(data))
                _ = parsed.get("status", {})
                if resp.status < 500:
                    err = None if resp.status == 200 else f"HTTP {resp.status}"
                    return SolrStatus(is_up=True, response_time=elapsed, checked_at=time.time(), error=err)
                return SolrStatus(is_up=False, response_time=elapsed, checked_at=time.time(), error=f"HTTP {resp.status}")
        except Exception:
            # If cores API unavailable, fall back to info/system probe
            try:
                url = f"http://localhost:{self._config.solr_port}/solr/admin/info/system"
                start = time.time()
                with urllib.request.urlopen(url, timeout=self._config.solr_timeout_seconds) as resp:
                    elapsed = time.time() - start
                    # Treat any HTTP response < 500 as service reachable; record non-200 as an error
                    if resp.status < 500:
                        err = None if resp.status == 200 else f"HTTP {resp.status}"
                        return SolrStatus(is_up=True, response_time=elapsed, checked_at=time.time(), error=err)
                    return SolrStatus(is_up=False, response_time=elapsed, checked_at=time.time(), error=f"HTTP {resp.status}")
            except urllib.error.HTTPError as he:
                # HTTPError raised for 4xx/5xx — treat <500 as reachable
                elapsed = time.time() - start
                code = getattr(he, 'code', None) or 0
                if code < 500:
                    return SolrStatus(is_up=True, response_time=elapsed, checked_at=time.time(), error=f"HTTP {code}")
                return SolrStatus(is_up=False, response_time=elapsed, checked_at=time.time(), error=f"HTTP {code}")
            except Exception as e:
                return SolrStatus(is_up=False, response_time=None, checked_at=time.time(), error=str(e))

    def get_status(self) -> SolrStatus:
        now_time = time.time()
        now_monotonic = time.monotonic()

        # Check if circuit breaker is open: skip HTTP probes and return cached DOWN status
        if self._circuit_open_until_monotonic > now_monotonic and self._status and not self._status.is_up:
            return self._status

        # Circuit breaker has expired; close it (only if it was actually open)
        if self._circuit_open_until_monotonic > 0.0 and self._circuit_open_until_monotonic <= now_monotonic:
            self._consecutive_down_checks = 0
            self._circuit_open_until_monotonic = 0.0

        if self._status and (now_time - self._status.checked_at) < (self._config.poll_interval * 0.8):
            return self._status

        self._status = self._probe()

        # Update circuit breaker state after probe
        if not self._status.is_up:
            self._consecutive_down_checks += 1
            # If threshold reached, open circuit
            if self._consecutive_down_checks >= self._DOWN_CIRCUIT_THRESHOLD:
                circuit_duration = max(
                    self._DOWN_CIRCUIT_MIN_INTERVAL_SECONDS,
                    self._config.poll_interval * self._DOWN_CIRCUIT_PROBE_INTERVAL_MULTIPLIER
                )
                self._circuit_open_until_monotonic = now_monotonic + circuit_duration
        else:
            # Solr recovered; close circuit and reset counter
            self._consecutive_down_checks = 0
            self._circuit_open_until_monotonic = 0.0

        return self._status
