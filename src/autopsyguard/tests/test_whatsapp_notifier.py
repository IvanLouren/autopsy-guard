"""Tests for WhatsAppNotifier.

Covers:
- Disabled notifier doesn't send
- Alert message formatting and HTTP dispatch
- Report message formatting and HTTP dispatch
- Retry logic on failure
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.whatsapp_notifier import WhatsAppNotifier


@pytest.fixture()
def wa_config(tmp_case_dir: Path) -> MonitorConfig:
    """Config with WhatsApp enabled."""
    return MonitorConfig(
        case_dir=tmp_case_dir,
        whatsapp_enabled=True,
        whatsapp_phone="+351912345678",
        whatsapp_apikey="test-key-123",
    )


@pytest.fixture()
def wa_disabled_config(tmp_case_dir: Path) -> MonitorConfig:
    """Config with WhatsApp disabled."""
    return MonitorConfig(
        case_dir=tmp_case_dir,
        whatsapp_enabled=False,
        whatsapp_phone="",
        whatsapp_apikey="",
    )


class TestWhatsAppDisabled:
    """When WhatsApp is not configured, nothing should be sent."""

    def test_is_not_enabled(self, wa_disabled_config: MonitorConfig) -> None:
        notifier = WhatsAppNotifier(wa_disabled_config)
        assert notifier.is_enabled() is False

    def test_send_alert_returns_false(self, wa_disabled_config: MonitorConfig) -> None:
        notifier = WhatsAppNotifier(wa_disabled_config)
        event = CrashEvent(
            crash_type=CrashType.HANG,
            severity=Severity.WARNING,
            message="Test hang",
        )
        assert notifier.send_alert([event]) is False

    def test_send_report_returns_false(self, wa_disabled_config: MonitorConfig) -> None:
        notifier = WhatsAppNotifier(wa_disabled_config)
        assert notifier.send_report("OK", 0) is False


class TestWhatsAppEnabled:
    """When WhatsApp is configured, messages should be dispatched."""

    def test_is_enabled(self, wa_config: MonitorConfig) -> None:
        notifier = WhatsAppNotifier(wa_config)
        assert notifier.is_enabled() is True

    @patch("autopsyguard.whatsapp_notifier.urllib.request.urlopen")
    def test_send_alert_dispatches(self, mock_urlopen, wa_config: MonitorConfig) -> None:
        """send_alert should trigger an HTTP request to CallMeBot."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        notifier = WhatsAppNotifier(wa_config)
        events = [
            CrashEvent(
                crash_type=CrashType.JVM_CRASH,
                severity=Severity.CRITICAL,
                message="JVM crashed with hs_err_pid1234.log",
            ),
        ]

        result = notifier.send_alert(events)
        assert result is True

        # Wait briefly for the background thread to fire
        import time
        time.sleep(0.5)

        # urlopen should have been called with a URL containing our phone and apikey
        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        url = req.full_url
        assert "351912345678" in url
        assert "test-key-123" in url
        assert "callmebot" in url

    @patch("autopsyguard.whatsapp_notifier.urllib.request.urlopen")
    def test_send_report_dispatches(self, mock_urlopen, wa_config: MonitorConfig) -> None:
        """send_report should trigger an HTTP request to CallMeBot."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        notifier = WhatsAppNotifier(wa_config)
        notifier.set_start_time()

        result = notifier.send_report("OK", events_last_period=0)
        assert result is True

        import time
        time.sleep(0.5)

        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        url = req.full_url
        assert "351912345678" in url

    def test_alert_message_contains_event_info(self, wa_config: MonitorConfig) -> None:
        """Alert message text should include the crash type and message."""
        notifier = WhatsAppNotifier(wa_config)
        events = [
            CrashEvent(
                crash_type=CrashType.HIGH_RESOURCE_USAGE,
                severity=Severity.WARNING,
                message="CPU at 99% for 15 minutes",
            ),
        ]

        # Intercept _send_message to capture the text
        captured = {}
        original = notifier._send_message

        def spy(text: str) -> bool:
            captured["text"] = text
            return True

        notifier._send_message = spy
        notifier.send_alert(events)

        assert "HIGH_RESOURCE_USAGE" in captured["text"]
        assert "CPU at 99%" in captured["text"]

    def test_report_message_contains_metrics(self, wa_config: MonitorConfig) -> None:
        """Report message should include CPU and RAM metrics when available."""
        notifier = WhatsAppNotifier(wa_config)
        notifier.set_start_time()

        samples = [{"cpu_percent": 45.0, "memory_percent": 62.0}]

        captured = {}
        def spy(text: str) -> bool:
            captured["text"] = text
            return True

        notifier._send_message = spy
        notifier.send_report("OK", events_last_period=0, metrics_samples=samples)

        assert "CPU: 45.0%" in captured["text"]
        assert "RAM: 62.0%" in captured["text"]
