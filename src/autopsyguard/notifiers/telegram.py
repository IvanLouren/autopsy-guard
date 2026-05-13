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
        lines.append("🚨 *AutopsyGuard ALERTA CRÍTICO*" if critical else "⚠️ *AutopsyGuard Aviso*")
        lines.append(f"📅 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        lines.append(f"Crítico(s): {len(critical)} | Aviso(s): {len(warnings)}")
        lines.append("")

        for event in events[:5]:
            icon = "🔴" if event.severity == Severity.CRITICAL else "🟡"
            lines.append(f"{icon} {event.crash_type.name}: {event.message[:100]}")

        if len(events) > 5:
            lines.append(f"... e mais {len(events) - 5} evento(s)")

        lines += ["", "Verifique o email para detalhes completos."]
        return self._send_message("\n".join(lines))

    def send_report(
        self,
        system_status: str,
        events_last_period: int,
        metrics_samples: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Send a periodic Telegram status summary."""
        if not self._enabled:
            return False

        status_icon = "✅" if events_last_period == 0 else "⚠️"
        status_text = "Tudo OK" if events_last_period == 0 else f"{events_last_period} evento(s)"

        lines = [
            "📊 *AutopsyGuard Relatório*",
            f"📅 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            "",
            f"{status_icon} Estado: {status_text}",
            f"⏱️ Uptime: {self.get_uptime()}",
            f"📈 Eventos no período: {events_last_period}",
        ]

        if metrics_samples:
            latest = metrics_samples[-1]
            cpu = latest.get("cpu_percent")
            mem = latest.get("memory_percent")
            if cpu is not None:
                lines.append(f"💻 CPU: {cpu:.1f}%")
            if mem is not None:
                lines.append(f"🧠 RAM: {mem:.1f}%")

        lines += ["", "Detalhes completos enviados por email."]
        return self._send_message("\n".join(lines))

    def send_ingest_report(self, duration_seconds: float) -> bool:
        """Send a report when an Autopsy ingest job finishes."""
        if not self._enabled:
            return False

        hours, rem = divmod(int(duration_seconds), 3600)
        minutes, seconds = divmod(rem, 60)
        duration_str = f"{hours}h {minutes}m {seconds}s"

        lines = [
            "🏁 *AutopsyGuard - Ingestão Concluída*",
            "O processo de ingestão no Autopsy terminou com sucesso.",
            "",
            f"⏱️ *Tempo Total:* {duration_str}",
        ]
        return self._send_message("\n".join(lines))

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
