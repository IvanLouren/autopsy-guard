"""Detect Solr service crashes and health issues.

Covers crash type:
  - Solr Subprocess Crash (via HTTP Health Checks)
"""

from __future__ import annotations

import logging
import urllib.request
import urllib.error

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity

logger = logging.getLogger(__name__)


class SolrDetector(BaseDetector):
    """Monitors the local Solr service via its HTTP REST API."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__(config)
        # We track if we already sent the alert so we don't spam the email every 10 seconds.
        self._solr_down_reported = False

    @property
    def name(self) -> str:
        return "SolrDetector"

    def check(self) -> list[CrashEvent]:
        events: list[CrashEvent] = []

        # Autopsy normally runs the internal Solr instance on localhost port 23232
        solr_url = "http://localhost:23232/solr/admin/info/system"
        
        try:
            # A healthy Solr instance will answer this ping almost instantaneously.
            # We give it a 3-second timeout before giving up.
            response = urllib.request.urlopen(solr_url, timeout=3.0)
            
            # If we reach here, Solr is fully alive (Status 200 OK)
            if response.status == 200:
                if self._solr_down_reported:
                    logger.info("Solr service has recovered and is responding on port 23232 again.")
                self._solr_down_reported = False
                
        except (urllib.error.URLError, ConnectionError) as e:
            # ConnectionRefusedError or Timeout means Solr is dead, frozen, or still booting up.
            if not self._solr_down_reported:
                events.append(CrashEvent(
                    crash_type=CrashType.SOLR_CRASH,
                    # Elevamos isto a CRITICAL porque se o Solr morre, a Pesquisa de Palavras-chave morre.
                    severity=Severity.CRITICAL, 
                    message=f"Solr API check failed! Service not responding on port 23232.",
                    details={"error": str(e), "url": solr_url},
                ))
                self._solr_down_reported = True

        return events
