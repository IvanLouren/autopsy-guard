"""Tests for SolrDetector."""

from __future__ import annotations

import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.solr_detector import SolrDetector
from autopsyguard.models import CrashType, Severity


class TestSolrHealthCheck:
    """Crash type: Solr subprocess crash."""

    def test_solr_healthy_no_event(self, config: MonitorConfig) -> None:
        """When Solr responds with 200 OK, no event should be generated."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_urlopen.return_value = mock_response

            events = detector.check()

        assert events == []
        assert detector._solr_down_reported is False

    def test_solr_down_triggers_critical_event(self, config: MonitorConfig) -> None:
        """When Solr is unreachable, a CRITICAL event should be generated."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

            events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.SOLR_CRASH
        assert events[0].severity == Severity.CRITICAL
        assert "Solr" in events[0].message
        assert detector._solr_down_reported is True

    def test_solr_down_only_reported_once(self, config: MonitorConfig) -> None:
        """Repeated failures should not generate duplicate events."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

            # First check should report
            events1 = detector.check()
            # Second check should not report again
            events2 = detector.check()

        assert len(events1) == 1
        assert len(events2) == 0
        assert detector._solr_down_reported is True

    def test_solr_recovery_resets_flag(self, config: MonitorConfig) -> None:
        """When Solr recovers, the reported flag should reset."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            # First, Solr is down
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
            events1 = detector.check()

            # Now Solr recovers
            mock_urlopen.side_effect = None
            mock_response = MagicMock()
            mock_response.status = 200
            mock_urlopen.return_value = mock_response

            events2 = detector.check()

        assert len(events1) == 1
        assert len(events2) == 0
        assert detector._solr_down_reported is False

    def test_solr_down_after_recovery_reports_again(self, config: MonitorConfig) -> None:
        """If Solr goes down again after recovering, a new event should be generated."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            # First failure
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
            events1 = detector.check()

            # Recovery
            mock_urlopen.side_effect = None
            mock_response = MagicMock()
            mock_response.status = 200
            mock_urlopen.return_value = mock_response
            detector.check()

            # Second failure
            mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
            events2 = detector.check()

        assert len(events1) == 1
        assert len(events2) == 1

    def test_connection_error_triggers_event(self, config: MonitorConfig) -> None:
        """ConnectionError should also trigger a CRITICAL event."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = ConnectionError("Connection failed")

            events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.SOLR_CRASH
        assert events[0].severity == Severity.CRITICAL

    def test_timeout_triggers_event(self, config: MonitorConfig) -> None:
        """Timeout should also trigger a CRITICAL event."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("timed out")

            events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.SOLR_CRASH

    def test_detector_name(self, config: MonitorConfig) -> None:
        """Verify the detector name property."""
        detector = SolrDetector(config)
        assert detector.name == "SolrDetector"
