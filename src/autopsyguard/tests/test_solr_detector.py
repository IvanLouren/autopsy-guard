"""Tests for SolrDetector."""

from __future__ import annotations

import socket
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.solr_detector import (
    SolrDetector,
    SOLR_SLOW_THRESHOLD_SECONDS,
    SOLR_SLOW_COUNT_THRESHOLD,
)
from autopsyguard.models import CrashType, Severity


class TestSolrHealthCheck:
    """Crash type: Solr subprocess crash."""

    def test_solr_healthy_no_event(self, config: MonitorConfig) -> None:
        """When Solr responds quickly with 200 OK, no event should be generated."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                # Simulate fast response (0.1s)
                mock_time.side_effect = [0.0, 0.1]
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
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                # First, Solr is down
                mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
                events1 = detector.check()

                # Now Solr recovers with fast response
                mock_urlopen.side_effect = None
                mock_time.side_effect = [0.0, 0.1]
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
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                # First failure - time.time() called twice (start + elapsed in exception handler)
                mock_time.side_effect = [0.0, 0.1]
                mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
                events1 = detector.check()

                # Recovery
                mock_time.side_effect = [0.0, 0.1]
                mock_urlopen.side_effect = None
                mock_response = MagicMock()
                mock_response.status = 200
                mock_urlopen.return_value = mock_response
                detector.check()

                # Second failure - time.time() called twice
                mock_time.side_effect = [0.0, 0.1]
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

    def test_detector_name(self, config: MonitorConfig) -> None:
        """Verify the detector name property."""
        detector = SolrDetector(config)
        assert detector.name == "SolrDetector"


class TestSolrHangDetection:
    """Solr hang detection via slow responses."""

    def test_slow_responses_trigger_hang_warning(self, config: MonitorConfig) -> None:
        """Multiple consecutive slow responses should trigger a HANG event."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                mock_response = MagicMock()
                mock_response.status = 200
                mock_urlopen.return_value = mock_response

                # Simulate slow responses (2.5s each)
                slow_time = SOLR_SLOW_THRESHOLD_SECONDS + 0.5
                all_events = []
                
                for i in range(SOLR_SLOW_COUNT_THRESHOLD):
                    mock_time.side_effect = [0.0, slow_time]
                    events = detector.check()
                    all_events.extend(events)

        # Should have exactly one HANG event after threshold reached
        hang_events = [e for e in all_events if e.crash_type == CrashType.HANG]
        assert len(hang_events) == 1
        assert hang_events[0].severity == Severity.WARNING
        assert "slow responses" in hang_events[0].message.lower()

    def test_fast_response_resets_slow_counter(self, config: MonitorConfig) -> None:
        """A fast response should reset the consecutive slow counter."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                mock_response = MagicMock()
                mock_response.status = 200
                mock_urlopen.return_value = mock_response

                # Two slow responses
                slow_time = SOLR_SLOW_THRESHOLD_SECONDS + 0.5
                mock_time.side_effect = [0.0, slow_time]
                detector.check()
                mock_time.side_effect = [0.0, slow_time]
                detector.check()
                
                assert detector._consecutive_slow_responses == 2

                # One fast response
                mock_time.side_effect = [0.0, 0.1]
                detector.check()

                assert detector._consecutive_slow_responses == 0

    def test_timeout_triggers_critical_hang(self, config: MonitorConfig) -> None:
        """A request timeout should trigger a CRITICAL hang event."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                # Simulate timeout
                mock_time.side_effect = [0.0, 5.0]
                timeout_error = urllib.error.URLError(socket.timeout("timed out"))
                mock_urlopen.side_effect = timeout_error

                events = detector.check()

        assert len(events) == 1
        assert events[0].crash_type == CrashType.HANG
        assert events[0].severity == Severity.CRITICAL
        assert "timed out" in events[0].message.lower()

    def test_hang_not_reported_twice(self, config: MonitorConfig) -> None:
        """Once a hang is reported, don't report again until recovery."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                mock_response = MagicMock()
                mock_response.status = 200
                mock_urlopen.return_value = mock_response

                slow_time = SOLR_SLOW_THRESHOLD_SECONDS + 0.5
                
                # Generate hang event
                for _ in range(SOLR_SLOW_COUNT_THRESHOLD):
                    mock_time.side_effect = [0.0, slow_time]
                    detector.check()

                assert detector._solr_hang_reported is True

                # More slow responses should not generate new events
                mock_time.side_effect = [0.0, slow_time]
                events = detector.check()

                assert events == []

    def test_hang_recovery_allows_new_report(self, config: MonitorConfig) -> None:
        """After hang recovery, a new hang should be reported."""
        detector = SolrDetector(config)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                mock_response = MagicMock()
                mock_response.status = 200
                mock_urlopen.return_value = mock_response

                slow_time = SOLR_SLOW_THRESHOLD_SECONDS + 0.5
                
                # Generate first hang
                for _ in range(SOLR_SLOW_COUNT_THRESHOLD):
                    mock_time.side_effect = [0.0, slow_time]
                    detector.check()

                # Fast response = recovery
                mock_time.side_effect = [0.0, 0.1]
                detector.check()
                
                assert detector._solr_hang_reported is False
                assert detector._consecutive_slow_responses == 0

                # New hang should be reported
                all_events = []
                for _ in range(SOLR_SLOW_COUNT_THRESHOLD):
                    mock_time.side_effect = [0.0, slow_time]
                    events = detector.check()
                    all_events.extend(events)

                hang_events = [e for e in all_events if e.crash_type == CrashType.HANG]
                assert len(hang_events) == 1
