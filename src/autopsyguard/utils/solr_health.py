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

    def _probe(self) -> SolrStatus:
        url = f"http://localhost:{self._config.solr_port}/solr/admin/info/system"
        start = time.time()
        try:
            with urllib.request.urlopen(url, timeout=self._config.solr_timeout_seconds) as resp:
                elapsed = time.time() - start
                if resp.status == 200:
                    return SolrStatus(is_up=True, response_time=elapsed, checked_at=time.time())
                return SolrStatus(is_up=False, response_time=elapsed, checked_at=time.time(), error=f"HTTP {resp.status}")
        except urllib.error.URLError as e:
            return SolrStatus(is_up=False, response_time=None, checked_at=time.time(), error=str(e))
        except Exception as e:
            return SolrStatus(is_up=False, response_time=None, checked_at=time.time(), error=str(e))

    def get_status(self) -> SolrStatus:
        now = time.time()
        if self._status and (now - self._status.checked_at) < (self._config.poll_interval * 0.8):
            return self._status
        self._status = self._probe()
        return self._status
