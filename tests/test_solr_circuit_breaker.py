"""Tests for Solr health cache circuit breaker."""
import time
from unittest.mock import MagicMock, patch

from autopsyguard.config import MonitorConfig
from autopsyguard.utils.solr_health import SolrHealthCache, SolrStatus


class TestSolrCircuitBreaker:
    """Test circuit breaker that skips probes when Solr is down for N consecutive checks."""

    def test_circuit_opens_after_threshold_consecutive_down_checks(self):
        """Circuit should open after 6 consecutive DOWN checks and skip subsequent probes."""
        config = MagicMock(spec=MonitorConfig)
        config.poll_interval = 5.0
        config.solr_port = 8983
        config.solr_timeout_seconds = 2.0

        cache = SolrHealthCache(config)

        down_status = SolrStatus(is_up=False, response_time=None, checked_at=time.time(), error="Connection refused")

        # Trigger 6 DOWN probes to open circuit
        # Invalidate cache by setting old timestamp so each get_status() calls _probe()
        with patch.object(cache, "_probe", return_value=down_status):
            for i in range(1, 7):  # 6 probes
                cache._status = None  # Force cache miss
                result = cache.get_status()
                assert not result.is_up
                assert cache._consecutive_down_checks == i, f"Expected {i}, got {cache._consecutive_down_checks}"

            assert cache._circuit_open_until_monotonic > 0.0

        # Now circuit is open; verify _probe() is NOT called on next get_status()
        with patch.object(cache, "_probe", wraps=cache._probe) as mock_probe:
            result = cache.get_status()
            assert not result.is_up  # Still returns cached DOWN status
            mock_probe.assert_not_called()  # Circuit prevents probe

    def test_circuit_duration_respects_minimum_interval(self):
        """Circuit should stay open for at least _DOWN_CIRCUIT_MIN_INTERVAL_SECONDS."""
        config = MagicMock(spec=MonitorConfig)
        config.poll_interval = 1.0  # Very short poll interval
        config.solr_port = 8983
        config.solr_timeout_seconds = 2.0

        cache = SolrHealthCache(config)
        down_status = SolrStatus(is_up=False, response_time=None, checked_at=time.time(), error="Down")

        # Trigger circuit open
        with patch.object(cache, "_probe", return_value=down_status):
            for _ in range(6):
                cache._status = None  # Force cache miss
                cache.get_status()

        # Circuit should be open for at least 30 seconds (minimum interval)
        circuit_duration = cache._circuit_open_until_monotonic - time.monotonic()
        assert circuit_duration >= SolrHealthCache._DOWN_CIRCUIT_MIN_INTERVAL_SECONDS - 0.1

    def test_circuit_closes_and_resets_on_successful_probe(self):
        """Circuit should close and counter reset when Solr recovers."""
        config = MagicMock(spec=MonitorConfig)
        config.poll_interval = 5.0
        config.solr_port = 8983
        config.solr_timeout_seconds = 2.0

        cache = SolrHealthCache(config)

        down_status = SolrStatus(is_up=False, response_time=None, checked_at=time.time(), error="Down")
        up_status = SolrStatus(is_up=True, response_time=0.1, checked_at=time.time(), error=None)

        # Open circuit with 6 DOWN probes
        with patch.object(cache, "_probe", return_value=down_status):
            for _ in range(6):
                cache._status = None  # Force cache miss
                cache.get_status()
            assert cache._consecutive_down_checks == 6
            assert cache._circuit_open_until_monotonic > 0.0

        # Recovery: Solr comes back UP
        with patch.object(cache, "_probe", return_value=up_status):
            cache._status = None  # Force cache miss
            result = cache.get_status()
            assert result.is_up
            assert cache._consecutive_down_checks == 0
            assert cache._circuit_open_until_monotonic == 0.0

    def test_circuit_expiration_closes_and_allows_probing(self):
        """When circuit timer expires, circuit closes and probing resumes."""
        config = MagicMock(spec=MonitorConfig)
        config.poll_interval = 5.0
        config.solr_port = 8983
        config.solr_timeout_seconds = 2.0

        cache = SolrHealthCache(config)

        down_status = SolrStatus(is_up=False, response_time=None, checked_at=time.time(), error="Down")

        # Open circuit
        with patch.object(cache, "_probe", return_value=down_status):
            for _ in range(6):
                cache._status = None  # Force cache miss
                cache.get_status()
            assert cache._circuit_open_until_monotonic > 0.0

        # Manually expire the circuit timer
        cache._circuit_open_until_monotonic = time.monotonic() - 1.0

        up_status = SolrStatus(is_up=True, response_time=0.1, checked_at=time.time(), error=None)

        # On next get_status(), circuit should close and allow probe
        with patch.object(cache, "_probe", return_value=up_status) as mock_probe:
            cache._status = None  # Force cache miss
            result = cache.get_status()
            mock_probe.assert_called_once()
            assert result.is_up
            assert cache._consecutive_down_checks == 0

    def test_up_check_does_not_increment_down_counter(self):
        """When Solr is UP, down counter should stay at 0."""
        config = MagicMock(spec=MonitorConfig)
        config.poll_interval = 5.0
        config.solr_port = 8983
        config.solr_timeout_seconds = 2.0

        cache = SolrHealthCache(config)

        up_status = SolrStatus(is_up=True, response_time=0.1, checked_at=time.time(), error=None)

        with patch.object(cache, "_probe", return_value=up_status):
            for _ in range(10):
                result = cache.get_status()
                assert result.is_up
                assert cache._consecutive_down_checks == 0

    def test_circuit_multiplier_applied_to_poll_interval(self):
        """Circuit duration should be poll_interval × multiplier (if greater than min)."""
        config = MagicMock(spec=MonitorConfig)
        config.poll_interval = 10.0
        config.solr_port = 8983
        config.solr_timeout_seconds = 2.0

        cache = SolrHealthCache(config)

        down_status = SolrStatus(is_up=False, response_time=None, checked_at=time.time(), error="Down")

        with patch.object(cache, "_probe", return_value=down_status):
            for _ in range(6):
                cache._status = None  # Force cache miss
                cache.get_status()

        # Expected duration: 10.0 * 5.0 = 50.0
        expected_duration = 10.0 * SolrHealthCache._DOWN_CIRCUIT_PROBE_INTERVAL_MULTIPLIER
        actual_duration = cache._circuit_open_until_monotonic - time.monotonic()
        assert abs(actual_duration - expected_duration) < 0.5  # Allow small timing variation
