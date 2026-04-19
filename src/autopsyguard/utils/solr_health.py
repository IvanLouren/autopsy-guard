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
    def __init__(self, config: MonitorConfig) -> None:
        self._config = config
        self._status: Optional[SolrStatus] = None
        # diagnostics removed

    def _probe(self) -> SolrStatus:
        # Lightweight liveness check: discover a core via the cores API,
        # then issue a /solr/{core}/admin/ping request. Fall back to the
        # heavier /solr/admin/info/system only if cores discovery fails.
        cores_url = f"http://localhost:{self._config.solr_port}/solr/admin/cores?action=STATUS&wt=json"
        try:
            start = time.time()
            with urllib.request.urlopen(cores_url, timeout=self._config.solr_timeout_seconds) as resp:
                elapsed = time.time() - start
                data = resp.read()
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

        # Parse cores API and pick first core name
        try:
            import json
            parsed = json.loads(data)
            status = parsed.get("status", {})
            cores = list(status.keys())
            if not cores:
                raise ValueError("no cores")
            core = cores[0]
            ping_url = f"http://localhost:{self._config.solr_port}/solr/{core}/admin/ping?wt=json"
            start = time.time()
            try:
                with urllib.request.urlopen(ping_url, timeout=self._config.solr_timeout_seconds) as presp:
                    elapsed = time.time() - start
                    # Consider any HTTP response < 500 as reachable (some cores return 4xx for malformed ping but Solr is alive)
                    if presp.status < 500:
                        err = None if presp.status == 200 else f"HTTP {presp.status}"
                        return SolrStatus(is_up=True, response_time=elapsed, checked_at=time.time(), error=err)
                    return SolrStatus(is_up=False, response_time=elapsed, checked_at=time.time(), error=f"HTTP {presp.status}")
            except urllib.error.HTTPError as he:
                elapsed = time.time() - start
                code = getattr(he, 'code', None) or 0
                if code < 500:
                    return SolrStatus(is_up=True, response_time=elapsed, checked_at=time.time(), error=f"HTTP {code}")
                return SolrStatus(is_up=False, response_time=elapsed, checked_at=time.time(), error=f"HTTP {code}")
        except Exception as e:
            return SolrStatus(is_up=False, response_time=None, checked_at=time.time(), error=str(e))

    def get_status(self) -> SolrStatus:
        now = time.time()
        if self._status and (now - self._status.checked_at) < (self._config.poll_interval * 0.8):
            return self._status
        self._status = self._probe()
        return self._status
