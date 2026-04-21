"""Tests for SolrDetector."""

from __future__ import annotations

import json
import socket
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import time
import os

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.solr_detector import (
    SolrDetector,
    SolrMetrics,
)
from autopsyguard.models import CrashType, Severity


def _patch_extra_checks(detector: SolrDetector) -> None:
    """Patch the metrics, cores, and logs checks to return empty lists.

    Used in tests that focus on the basic health/hang detection.
    """
    detector._check_metrics = lambda: []
    detector._check_cores = lambda: []
    detector._check_logs = lambda: []


class TestSolrHealthCheck:
    """Crash type: Solr subprocess crash."""

    def test_solr_healthy_no_event(self, config: MonitorConfig) -> None:
        """When Solr responds quickly with 200 OK, no event should be generated."""
        detector = SolrDetector(config)
        _patch_extra_checks(detector)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                # Simulate fast response for both cores discovery and ping.
                mock_time.side_effect = [0.0, 0.01, 0.02, 0.03]
                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                cores_response.__enter__.return_value = cores_response
                cores_response.__enter__.return_value = cores_response
                cores_response.__enter__.return_value = cores_response
                cores_response.__enter__.return_value = cores_response
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response
                ping_response.__enter__.return_value = ping_response
                ping_response.__enter__.return_value = ping_response
                # Repeat cores+ping for each check
                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                g = _gen()
                mock_urlopen.side_effect = lambda *a, **k: next(g)

                events = detector.check()

        assert events == []
        assert detector._solr_down_reported is False

    def test_solr_down_triggers_critical_event(self, config: MonitorConfig) -> None:
        """When Solr is unreachable, a CRITICAL event should be generated."""
        detector = SolrDetector(config)
        _patch_extra_checks(detector)

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
        _patch_extra_checks(detector)

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
        _patch_extra_checks(detector)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                # First, Solr is down
                mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
                events1 = detector.check()

                # Now Solr recovers with fast response (explicit cores+ping)
                mock_time.side_effect = [0.0, 0.01, 0.02, 0.03]
                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response
                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                g = _gen()
                mock_urlopen.side_effect = lambda *a, **k: next(g)

                events2 = detector.check()

        assert len(events1) == 1
        assert len(events2) == 0
        assert detector._solr_down_reported is False

    def test_solr_down_after_recovery_reports_again(self, config: MonitorConfig) -> None:
        """If Solr goes down again after recovering, a new event should be generated."""
        detector = SolrDetector(config)
        _patch_extra_checks(detector)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                # First failure - time.time() called twice (start + elapsed in exception handler)
                mock_time.side_effect = [0.0, 0.1]
                mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
                events1 = detector.check()

                # Recovery (explicit cores+ping)
                mock_time.side_effect = [0.0, 0.01, 0.02]
                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response
                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                g = _gen()
                mock_urlopen.side_effect = lambda *a, **k: next(g)
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
        _patch_extra_checks(detector)

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
        _patch_extra_checks(detector)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                # Provide explicit cores + ping responses
                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response
                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                g = _gen()
                mock_urlopen.side_effect = lambda *a, **k: next(g)

                # Simulate slow responses (each ping takes `slow_time`)
                slow_time = config.solr_slow_threshold_seconds + 0.5
                all_events = []

                for _ in range(config.solr_slow_count_threshold):
                    mock_time.side_effect = [0.0, 0.01, slow_time]
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
        _patch_extra_checks(detector)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response
                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                g = _gen()
                mock_urlopen.side_effect = lambda *a, **k: next(g)

                # Two slow responses
                slow_time = config.solr_slow_threshold_seconds + 0.5
                mock_time.side_effect = [0.0, 0.01, slow_time]
                detector.check()
                mock_time.side_effect = [0.0, 0.01, slow_time]
                detector.check()

                assert detector._consecutive_slow_responses == 2

                # One fast response
                mock_time.side_effect = [0.0, 0.01, 0.1]
                detector.check()

                assert detector._consecutive_slow_responses == 0

    def test_timeout_triggers_critical_hang(self, config: MonitorConfig) -> None:
        """A request timeout should trigger a CRITICAL hang event."""
        detector = SolrDetector(config)
        _patch_extra_checks(detector)

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
        _patch_extra_checks(detector)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response
                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                g = _gen()
                def _urlopen(url, timeout=None):
                    print("URLOPEN", url)
                    return next(g)
                mock_urlopen.side_effect = _urlopen

                slow_time = config.solr_slow_threshold_seconds + 0.5

                # Generate hang event
                for _ in range(config.solr_slow_count_threshold):
                    mock_time.side_effect = [0.0, 0.01, slow_time]
                    detector.check()

                assert detector._solr_hang_reported is True

                # More slow responses should not generate new events
                mock_time.side_effect = [0.0, 0.01, slow_time]
                events = detector.check()

                assert events == []

    def test_hang_recovery_allows_new_report(self, config: MonitorConfig) -> None:
        """After hang recovery, a new hang should be reported."""
        detector = SolrDetector(config)
        _patch_extra_checks(detector)

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response
                ping_response.__enter__.return_value = ping_response
                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                g = _gen()
                mock_urlopen.side_effect = lambda *a, **k: next(g)

                slow_time = config.solr_slow_threshold_seconds + 0.5

                # Generate first hang
                for _ in range(config.solr_slow_count_threshold):
                    mock_time.side_effect = [0.0, 0.01, slow_time]
                    detector.check()

                # Fast response = recovery
                mock_time.side_effect = [0.0, 0.01, 0.1]
                detector.check()

                assert detector._solr_hang_reported is False
                assert detector._consecutive_slow_responses == 0

                # New hang should be reported
                all_events = []
                for _ in range(config.solr_slow_count_threshold):
                    mock_time.side_effect = [0.0, 0.01, slow_time]
                    events = detector.check()
                    all_events.extend(events)

                hang_events = [e for e in all_events if e.crash_type == CrashType.HANG]
                assert len(hang_events) == 1


class TestSolrMetrics:
    """Tests for Solr metrics monitoring via admin API."""

    def _make_metrics_response(
        self,
        heap_used: int = 500 * 1024 * 1024,
        heap_max: int = 1024 * 1024 * 1024,
        cpu_load: float = 0.25,
        thread_count: int = 50,
    ) -> bytes:
        """Create a mock Solr metrics API response."""
        data = {
            "metrics": {
                "solr.jvm": {
                    "memory.heap.used": heap_used,
                    "memory.heap.max": heap_max,
                    "os.processCpuLoad": cpu_load,
                    "threads.count": thread_count,
                    "gc.G1-Young-Generation.count": 10,
                    "gc.G1-Young-Generation.time": 500,
                }
            }
        }
        return json.dumps(data).encode("utf-8")

    def test_metrics_normal_no_event(self, config: MonitorConfig) -> None:
        """Normal metrics should not generate any events."""
        detector = SolrDetector(config)
        detector._check_cores = lambda: []
        detector._check_logs = lambda: []

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                # Provide explicit cores + ping + metrics responses
                mock_time.side_effect = [0.0, 0.01, 0.02]

                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response

                # Metrics response (50% heap, 25% CPU)
                metrics_response = MagicMock()
                metrics_response.read.return_value = self._make_metrics_response()

                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                        yield metrics_response
                g = _gen()
                def _urlopen(url, timeout=None):
                    print('URLOPEN', url)
                    return next(g)
                mock_urlopen.side_effect = _urlopen

                events = detector.check()
                print('EVENTS', events)

        # No events for normal metrics
        resource_events = [e for e in events if e.crash_type == CrashType.HIGH_RESOURCE_USAGE]
        assert len(resource_events) == 0

    def test_high_heap_usage_warning(self, config: MonitorConfig) -> None:
        """High heap usage should trigger a WARNING event."""
        detector = SolrDetector(config)
        detector._check_cores = lambda: []
        detector._check_logs = lambda: []

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                mock_time.side_effect = [0.0, 0.01, 0.02]

                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response

                # 90% heap usage (above warning threshold)
                metrics_response = MagicMock()
                metrics_response.read.return_value = self._make_metrics_response(
                    heap_used=900 * 1024 * 1024,
                    heap_max=1024 * 1024 * 1024,
                )

                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                        yield metrics_response
                g = _gen()
                def _urlopen(url, timeout=None):
                    print('URLOPEN', url)
                    return next(g)
                mock_urlopen.side_effect = _urlopen

                events = detector.check()
                print('EVENTS', events)

        resource_events = [e for e in events if e.crash_type == CrashType.HIGH_RESOURCE_USAGE]
        assert len(resource_events) == 1
        assert resource_events[0].severity == Severity.WARNING
        assert "heap" in resource_events[0].message.lower()

    def test_critical_heap_usage(self, config: MonitorConfig) -> None:
        """Critical heap usage should trigger a CRITICAL event."""
        detector = SolrDetector(config)
        detector._check_cores = lambda: []
        detector._check_logs = lambda: []

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                mock_time.side_effect = [0.0, 0.01, 0.02]

                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response
                ping_response.__enter__.return_value = ping_response

                # 97% heap usage (above critical threshold)
                metrics_response = MagicMock()
                metrics_response.read.return_value = self._make_metrics_response(
                    heap_used=970 * 1024 * 1024,
                    heap_max=1000 * 1024 * 1024,
                )

                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                        yield metrics_response
                g = _gen()
                mock_urlopen.side_effect = lambda *a, **k: next(g)

                events = detector.check()

        resource_events = [e for e in events if e.crash_type == CrashType.HIGH_RESOURCE_USAGE]
        assert len(resource_events) == 1
        assert resource_events[0].severity == Severity.CRITICAL

    def test_high_cpu_warning(self, config: MonitorConfig) -> None:
        """High CPU usage should trigger a WARNING event."""
        detector = SolrDetector(config)
        detector._check_cores = lambda: []
        detector._check_logs = lambda: []

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                mock_time.side_effect = [0.0, 0.01, 0.02]

                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200

                # 95% CPU usage
                metrics_response = MagicMock()
                metrics_response.read.return_value = self._make_metrics_response(
                    cpu_load=0.95,
                )

                def _gen():
                    while True:
                        yield cores_response
                        yield ping_response
                        yield metrics_response
                g = _gen()
                mock_urlopen.side_effect = lambda *a, **k: next(g)

                events = detector.check()

        cpu_events = [
            e for e in events
            if e.crash_type == CrashType.HIGH_RESOURCE_USAGE and "cpu" in e.message.lower()
        ]
        assert len(cpu_events) == 1
        assert cpu_events[0].severity == Severity.WARNING

    def test_metrics_not_reported_twice(self, config: MonitorConfig) -> None:
        """Resource warnings should not be reported repeatedly."""
        detector = SolrDetector(config)
        detector._check_cores = lambda: []
        detector._check_logs = lambda: []

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                health_response = MagicMock()
                health_response.status = 200

                # 90% heap usage
                metrics_response = MagicMock()
                metrics_response.read.return_value = self._make_metrics_response(
                    heap_used=900 * 1024 * 1024,
                    heap_max=1024 * 1024 * 1024,
                )

                # First check (explicit cores+ping+metrics)
                mock_time.side_effect = [0.0, 0.01, 0.02]
                cores_response = MagicMock()
                cores_response.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response.status = 200
                cores_response.__enter__.return_value = cores_response
                ping_response = MagicMock()
                ping_response.status = 200
                ping_response.__enter__.return_value = ping_response
                mock_urlopen.side_effect = [cores_response, ping_response, metrics_response]
                events1 = detector.check()

                # Second check with same high heap
                mock_time.side_effect = [0.0, 0.01, 0.02]
                cores_response2 = MagicMock()
                cores_response2.read.return_value = b'{"status": {"core0": {}}, "initFailures": {}}'
                cores_response2.status = 200
                cores_response2.__enter__.return_value = cores_response2
                ping_response2 = MagicMock()
                ping_response2.status = 200
                ping_response2.__enter__.return_value = ping_response2
                def _gen2():
                    while True:
                        yield cores_response2
                        yield ping_response2
                        yield metrics_response
                g2 = _gen2()
                mock_urlopen.side_effect = lambda *a, **k: next(g2)
                events2 = detector.check()

        # First check should report, second should not
        assert len([e for e in events1 if e.crash_type == CrashType.HIGH_RESOURCE_USAGE]) == 1
        assert len([e for e in events2 if e.crash_type == CrashType.HIGH_RESOURCE_USAGE]) == 0

    def test_parse_metrics_handles_value_objects(self, config: MonitorConfig) -> None:
        """Metrics parser should handle both direct values and value objects."""
        detector = SolrDetector(config)

        # Solr can return metrics as {"value": X} or just X
        data = {
            "metrics": {
                "solr.jvm": {
                    "memory.heap.used": {"value": 500 * 1024 * 1024},
                    "memory.heap.max": {"value": 1024 * 1024 * 1024},
                    "os.processCpuLoad": {"value": 0.5},
                    "threads.count": {"value": 100},
                }
            }
        }

        metrics = detector._parse_metrics(data)

        assert metrics.heap_used_mb == pytest.approx(500, rel=0.01)
        assert metrics.heap_max_mb == pytest.approx(1024, rel=0.01)
        assert metrics.heap_usage_percent == pytest.approx(48.8, rel=0.1)
        assert metrics.cpu_percent == pytest.approx(50, rel=0.01)
        assert metrics.thread_count == 100


class TestSolrCoreStatus:
    """Tests for Solr core status monitoring."""

    def test_core_init_failure_triggers_event(self, config: MonitorConfig) -> None:
        """Core initialization failure should trigger a CRITICAL event."""
        detector = SolrDetector(config)
        detector._check_metrics = lambda: []
        detector._check_logs = lambda: []

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                mock_time.side_effect = [0.0, 0.1]

                health_response = MagicMock()
                health_response.status = 200

                # Cores response with init failure
                cores_data = {
                    "status": {
                        "textsearch": {
                            "index": {"numDocs": 1000, "sizeInBytes": 1024000}
                        }
                    },
                    "initFailures": {
                        "textsearch": "org.apache.solr.common.SolrException: Index locked"
                    }
                }
                cores_response = MagicMock()
                cores_response.read.return_value = json.dumps(cores_data).encode("utf-8")

                def _gen():
                    while True:
                        yield health_response
                        yield cores_response
                g = _gen()
                mock_urlopen.side_effect = lambda *a, **k: next(g)

                events = detector.check()

        solr_events = [e for e in events if e.crash_type == CrashType.SOLR_CRASH]
        assert len(solr_events) == 1
        assert solr_events[0].severity == Severity.CRITICAL
        assert "textsearch" in solr_events[0].message

    def test_healthy_cores_no_event(self, config: MonitorConfig) -> None:
        """Healthy cores should not generate any events."""
        detector = SolrDetector(config)
        detector._check_metrics = lambda: []
        detector._check_logs = lambda: []

        with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
            with patch("autopsyguard.detectors.solr_detector.time.time") as mock_time:
                mock_time.side_effect = [0.0, 0.1]

                health_response = MagicMock()
                health_response.status = 200

                # Healthy cores response
                cores_data = {
                    "status": {
                        "textsearch": {
                            "index": {
                                "numDocs": 1000,
                                "sizeInBytes": 1024000,
                                "hasDeletions": False
                            }
                        }
                    },
                    "initFailures": {}
                }
                cores_response = MagicMock()
                cores_response.read.return_value = json.dumps(cores_data).encode("utf-8")

                def _gen():
                    while True:
                        yield health_response
                        yield cores_response
                g = _gen()
                mock_urlopen.side_effect = lambda *a, **k: next(g)

                events = detector.check()

        solr_events = [e for e in events if e.crash_type == CrashType.SOLR_CRASH]
        assert len(solr_events) == 0


class TestSolrLogMonitoring:
    """Tests for Solr log file monitoring."""

    def test_error_in_log_triggers_event(self, config: MonitorConfig, tmp_path: Path) -> None:
        """ERROR entry in Solr log should trigger a CRITICAL event."""
        detector = SolrDetector(config)
        detector._check_metrics = lambda: []
        detector._check_cores = lambda: []

        # Create fake log directory and file
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "solr.log"

        with patch("autopsyguard.detectors.solr_detector.get_solr_log_dir") as mock_log_dir:
            mock_log_dir.return_value = log_dir

            # Need to bypass the health check since we're testing logs directly
            with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

                # First check initializes (no errors yet)
                log_file.write_text("")
                detector.check()

                # Now write error and check again
                log_file.write_text("2024-01-01 ERROR SolrCore Something bad happened\n")
                events = detector.check()

        log_events = [e for e in events if e.crash_type == CrashType.LOG_ERROR]
        assert len(log_events) == 1
        assert log_events[0].severity == Severity.CRITICAL
        assert "solr.log" in log_events[0].message

    def test_oom_in_log_triggers_critical(self, config: MonitorConfig, tmp_path: Path) -> None:
        """OutOfMemoryError in logs should trigger a CRITICAL event."""
        detector = SolrDetector(config)
        detector._check_metrics = lambda: []
        detector._check_cores = lambda: []

        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "solr.log"

        with patch("autopsyguard.detectors.solr_detector.get_solr_log_dir") as mock_log_dir:
            mock_log_dir.return_value = log_dir

            with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

                # First check initializes
                log_file.write_text("")
                detector.check()

                # Now write OOM error and check again
                log_file.write_text("2024-01-01 java.lang.OutOfMemoryError: Java heap space\n")
                events = detector.check()

        log_events = [e for e in events if e.crash_type == CrashType.LOG_ERROR]
        assert len(log_events) == 1
        assert log_events[0].severity == Severity.CRITICAL

    def test_log_incremental_reading(self, config: MonitorConfig, tmp_path: Path) -> None:
        """Log reader should only read new content, not re-read old errors."""
        detector = SolrDetector(config)
        detector._check_metrics = lambda: []
        detector._check_cores = lambda: []

        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "solr.log"

        with patch("autopsyguard.detectors.solr_detector.get_solr_log_dir") as mock_log_dir:
            mock_log_dir.return_value = log_dir

            with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.URLError("x")

                # First check initializes (empty log)
                log_file.write_text("")
                detector.check()

                # Write first error
                log_file.write_text("2024-01-01 ERROR First error\n")
                events1 = detector.check()

                # Add new error
                with open(log_file, "a") as f:
                    f.write("2024-01-01 ERROR Second error\n")

                # Third check should only see second error
                events2 = detector.check()

        assert len([e for e in events1 if e.crash_type == CrashType.LOG_ERROR]) == 1
        assert len([e for e in events2 if e.crash_type == CrashType.LOG_ERROR]) == 1

    def test_solr_log_ignores_preexisting_rotated_file(self, config: MonitorConfig, tmp_path: Path) -> None:
        """Rotated file predating monitor start should be skipped."""
        # Prepare log and state directories
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "solr.log.1"

        # Write small file content and set mtime to an old time
        log_file.write_text("Old content\n")
        old_mtime = 1000000000.0  # 2001-09-09
        import os
        os.utime(log_file, (old_mtime, old_mtime))

        # Create state file indicating a previous read position larger than current file size
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        state_file = state_dir / "solr_log_positions.json"
        # Large offset to simulate previous position beyond current file size
        state_file.write_text(str({str(log_file): 9999}).replace("'", '"'))

        # Monitor started after the file mtime so rotated file is considered historical
        monitor_start = old_mtime + 1000.0

        detector = SolrDetector(config, monitor_start=monitor_start)
        detector._check_metrics = lambda: []
        detector._check_cores = lambda: []

        with patch("autopsyguard.detectors.solr_detector.get_solr_log_dir") as mock_log_dir:
            mock_log_dir.return_value = log_dir
            with patch("autopsyguard.detectors.solr_detector.get_autopsyguard_state_dir") as mock_state_dir:
                mock_state_dir.return_value = state_dir
                with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
                    mock_urlopen.side_effect = urllib.error.URLError("x")

                    # First check should load positions and skip rotated historical file
                    events = detector.check()

        # No log events should be produced and the tracker should have set the offset to EOF
        log_events = [e for e in events if e.crash_type == CrashType.LOG_ERROR]
        assert len(log_events) == 0
        # Verify tracker recorded EOF position
        pos = detector._log_tracker.get_position(log_file)
        assert pos == log_file.stat().st_size

    def test_solr_log_filters_lines_before_monitor_start(self, config: MonitorConfig, tmp_path: Path) -> None:
        """Log lines timestamped before monitor_start should not generate events."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        log_file = log_dir / "solr.log"

        # Compose timestamps relative to now
        from datetime import datetime, timedelta
        now = time.time()
        old_dt = datetime.fromtimestamp(now - 5)
        new_dt = datetime.fromtimestamp(now + 5)
        old_ts = old_dt.strftime("%Y-%m-%d %H:%M:%S")
        new_ts = new_dt.strftime("%Y-%m-%d %H:%M:%S")

        # Write two lines: one before monitor_start, one after
        log_file.write_text(f"{old_ts} ERROR Old error\n{new_ts} ERROR New error\n")

        # Ensure file mtime is newer than monitor_start so file is read
        os.utime(log_file, None)

        monitor_start = now

        detector = SolrDetector(config, monitor_start=monitor_start)
        detector._initialized = True
        detector._check_metrics = lambda: []
        detector._check_cores = lambda: []

        with patch("autopsyguard.detectors.solr_detector.get_solr_log_dir") as mock_log_dir:
            mock_log_dir.return_value = log_dir
            with patch("autopsyguard.detectors.solr_detector.get_autopsyguard_state_dir") as mock_state_dir:
                mock_state_dir.return_value = tmp_path / "state"
                with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
                    mock_urlopen.side_effect = urllib.error.URLError("x")

                    events = detector.check()

        log_events = [e for e in events if e.crash_type == CrashType.LOG_ERROR]
        # Only the new line should generate an event
        assert len(log_events) == 1
        assert "New error" in log_events[0].details.get("log_line", "")

    def test_missing_log_dir_no_error(self, config: MonitorConfig, tmp_path: Path) -> None:
        """Missing log directory should not cause errors."""
        detector = SolrDetector(config)
        detector._check_metrics = lambda: []
        detector._check_cores = lambda: []

        non_existent = tmp_path / "does_not_exist"

        with patch("autopsyguard.detectors.solr_detector.get_solr_log_dir") as mock_log_dir:
            mock_log_dir.return_value = non_existent

            with patch("autopsyguard.detectors.solr_detector.urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.URLError("x")

                # Should not raise
                events = detector.check()

        log_events = [e for e in events if e.crash_type == CrashType.LOG_ERROR]
        assert len(log_events) == 0


class TestSolrMetricsDataclass:
    """Tests for SolrMetrics dataclass."""

    def test_default_values(self) -> None:
        """SolrMetrics should have sensible defaults."""
        metrics = SolrMetrics()
        assert metrics.heap_used_mb == 0.0
        assert metrics.heap_max_mb == 0.0
        assert metrics.heap_usage_percent == 0.0
        assert metrics.cpu_percent == 0.0
        assert metrics.thread_count == 0
        assert metrics.gc_count == 0
        assert metrics.gc_time_ms == 0

    def test_custom_values(self) -> None:
        """SolrMetrics should accept custom values."""
        metrics = SolrMetrics(
            heap_used_mb=512.0,
            heap_max_mb=1024.0,
            heap_usage_percent=50.0,
            cpu_percent=25.0,
            thread_count=100,
            gc_count=50,
            gc_time_ms=1000,
        )
        assert metrics.heap_used_mb == 512.0
        assert metrics.heap_max_mb == 1024.0
        assert metrics.heap_usage_percent == 50.0
        assert metrics.cpu_percent == 25.0
        assert metrics.thread_count == 100
        assert metrics.gc_count == 50
        assert metrics.gc_time_ms == 1000

