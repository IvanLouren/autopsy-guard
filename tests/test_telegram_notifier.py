from __future__ import annotations

from pathlib import Path

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.notifiers.telegram import TelegramNotifier


@pytest.fixture()
def tg_config(tmp_case_dir: Path) -> MonitorConfig:
    return MonitorConfig(
        case_dir=tmp_case_dir,
        telegram_enabled=True,
        telegram_user="@tester",
    )


def test_telegram_alert_message_localized_en(tg_config: MonitorConfig) -> None:
    notifier = TelegramNotifier(tg_config)
    events = [CrashEvent(crash_type=CrashType.HANG, severity=Severity.WARNING, message="Possible hang")]

    captured = {}

    def spy(text: str) -> bool:
        captured["text"] = text
        return True

    notifier._send_message = spy
    assert notifier.send_alert(events) is True
    assert "AutopsyGuard Warning" in captured["text"]
    assert "Check email for full details." in captured["text"]


def test_telegram_report_message_is_english_only(tmp_case_dir: Path) -> None:
    cfg = MonitorConfig(case_dir=tmp_case_dir, telegram_enabled=True, telegram_user="@tester")
    notifier = TelegramNotifier(cfg)
    notifier.set_start_time()

    captured = {}

    def spy(text: str) -> bool:
        captured["text"] = text
        return True

    notifier._send_message = spy
    assert notifier.send_report("OK", events_last_period=1, metrics_samples=[{"cpu_percent": 12.0, "memory_percent": 34.0}]) is True
    assert "Status" in captured["text"]
    assert "Full details sent by email." in captured["text"]

