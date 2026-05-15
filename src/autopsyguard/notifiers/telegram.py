"""Telegram notification channel for AutopsyGuard.

Sends plain-text alert and status messages via the CallMeBot free webhook API.

Setup:
    1. Send a message to @CallMeBot_txtbot on Telegram
    2. Put your telegram username (e.g. @yourusername) or phone number in
       config as ``telegram_user``
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, Severity
from autopsyguard.notifiers.base import BaseNotifier
from autopsyguard.utils.i18n import tr

logger = logging.getLogger(__name__)

_CALLMEBOT_TELEGRAM_URL = "https://api.callmebot.com/text.php"


class TelegramNotifier(BaseNotifier):
    """Sends Telegram messages via the CallMeBot webhook API."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__()
        self.config = config
        self._enabled = bool(config.telegram_enabled and config.telegram_user)

    def is_enabled(self) -> bool:
        return self._enabled

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_alert(self, events: list[CrashEvent]) -> bool:
        """Send an immediate Telegram alert for critical/warning events."""
        if not self._enabled or not events:
            return False

        critical = [e for e in events if e.severity == Severity.CRITICAL]
        warnings = [e for e in events if e.severity == Severity.WARNING]

        lines: list[str] = []
        lines.append(
            f"🚨 *{tr(self.config, 'wa_alert_critical_title')}*"
            if critical else f"⚠️ *{tr(self.config, 'wa_alert_warning_title')}*"
        )
        lines.append(f"📅 {tr(self.config, 'wa_timestamp')}: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        lines.append(
            f"{tr(self.config, 'wa_critical_count')}: {len(critical)} | "
            f"{tr(self.config, 'wa_warning_count')}: {len(warnings)}"
        )
        lines.append("")

        for event in events[:5]:
            icon = "🔴" if event.severity == Severity.CRITICAL else "🟡"
            lines.append(f"{icon} {event.crash_type.name}: {event.message[:100]}")

        if len(events) > 5:
            lines.append(tr(self.config, "wa_more_events", count=len(events) - 5))

        lines += ["", tr(self.config, "wa_check_email")]
        return self._send_message("\n".join(lines))

    def send_report(
        self,
        system_status: str,
        events_last_period: int,
        metrics_samples: list[dict[str, Any]] | None = None,
        telemetry: dict[str, Any] | None = None,
    ) -> bool:
        """Send a periodic Telegram status summary."""
        if not self._enabled:
            return False

        status_icon = "✅" if events_last_period == 0 else "⚠️"
        status_text = tr(self.config, "all_ok") if events_last_period == 0 else tr(self.config, "events_count", count=events_last_period)

        lines = [
            f"📊 *{tr(self.config, 'wa_report_title')}*",
            f"📅 {tr(self.config, 'wa_timestamp')}: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            "",
            f"{status_icon} {tr(self.config, 'wa_status_label')}: {status_text}",
            f"⏱️ {tr(self.config, 'wa_uptime_label')}: {self.get_uptime()}",
            f"📈 {tr(self.config, 'wa_events_period_label')}: {events_last_period}",
        ]

        if metrics_samples:
            latest = metrics_samples[-1]
            cpu = latest.get("cpu_percent")
            mem = latest.get("memory_percent")
            if cpu is not None:
                lines.append(f"💻 {tr(self.config, 'wa_cpu_label')}: {cpu:.1f}%")
            if mem is not None:
                lines.append(f"🧠 {tr(self.config, 'wa_ram_label')}: {mem:.1f}%")

        if telemetry:
            solr = telemetry.get("solr", {})
            cpu_tl = telemetry.get("autopsy_cpu_timeline", {})
            state = tr(self.config, "solr_up") if solr.get("state") == "up" else tr(self.config, "solr_down")
            lines.append(f"🔬 {tr(self.config, 'wa_solr_label')}: {state}")
            curr = cpu_tl.get("current")
            if curr is not None:
                lines.append(f"🖥️ {tr(self.config, 'wa_autopsy_cpu_label')}: {curr:.1f}%")

        lines += ["", tr(self.config, "wa_details_email")]
        return self._send_message("\n".join(lines))

    def send_ingest_report(self, duration_seconds: float) -> bool:
        """Send a report when an Autopsy ingest job finishes."""
        if not self._enabled:
            return False

        hours, rem = divmod(int(duration_seconds), 3600)
        minutes, seconds = divmod(rem, 60)
        duration_str = f"{hours}h {minutes}m {seconds}s"

        lines = [
            f"🏁 *AutopsyGuard - {tr(self.config, 'ingest_done_title')}*",
            tr(self.config, "ingest_done_text"),
            "",
            f"⏱️ *{tr(self.config, 'processing_time')}:* {duration_str}",
        ]
        return self._send_message("\n".join(lines))

    def send_startup_message(self) -> bool:
        """Send a brief notification that the monitor has started."""
        if not self._enabled:
            return False
        return self._send_message(f"✅ *AutopsyGuard {tr(self.config, 'startup_subject')}*\n{tr(self.config, 'startup_text')}")

    # ------------------------------------------------------------------
    # Internal: HTTP dispatch (runs in background thread)
    # ------------------------------------------------------------------

    def _send_message(self, text: str) -> bool:
        """Enqueue a message send in a background thread. Always returns True."""
        def _do_send() -> bool:
            params = urllib.parse.urlencode({
                "user": self.config.telegram_user,
                "text": text,
            })
            url = f"{_CALLMEBOT_TELEGRAM_URL}?{params}"
            max_attempts, base_backoff = 3, 2.0
            last_exc: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    logger.debug("Telegram send attempt %d/%d", attempt, max_attempts)
                    req = urllib.request.Request(url, method="GET")
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        if resp.status == 200:
                            logger.info("📱 Telegram message sent successfully")
                            return True
                        logger.warning("Telegram API returned status %d (attempt %d)", resp.status, attempt)
                except Exception as e:
                    last_exc = e
                    logger.warning("Telegram send failed (attempt %d/%d): %s", attempt, max_attempts, e)
                if attempt < max_attempts:
                    time.sleep(base_backoff * (2 ** (attempt - 1)))
            logger.error("❌ Telegram message failed after %d attempts: %s", max_attempts, last_exc)
            return False

        threading.Thread(target=_do_send, daemon=True).start()
        return True
