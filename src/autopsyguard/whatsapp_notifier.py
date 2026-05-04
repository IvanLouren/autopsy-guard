"""WhatsApp notification channel for AutopsyGuard.

Sends plain-text alert and status messages via the CallMeBot free webhook API.
No external dependencies — uses only Python's built-in urllib.

Setup:
    1. Save +34 644 31 82 94 in your phone contacts as "CallMeBot"
    2. Send "I allow callmebot to send me messages" to that number on WhatsApp
    3. You'll receive an API key — put it in config as ``whatsapp_apikey``
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

logger = logging.getLogger(__name__)

# CallMeBot endpoint
_CALLMEBOT_URL = "https://api.callmebot.com/whatsapp.php"


class WhatsAppNotifier:
    """Sends WhatsApp messages via the CallMeBot webhook API."""

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self._enabled = bool(
            config.whatsapp_enabled
            and config.whatsapp_phone
            and config.whatsapp_apikey
        )
        self._start_time: datetime | None = None

    def is_enabled(self) -> bool:
        """Check if WhatsApp notifications are configured and enabled."""
        return self._enabled

    def set_start_time(self) -> None:
        """Set the notifier's start time for uptime tracking."""
        self._start_time = datetime.now()

    def get_uptime(self) -> str:
        """Return formatted uptime string."""
        if self._start_time is None:
            return "N/A"
        delta = datetime.now() - self._start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"

    # ------------------------------------------------------------------
    # Public API — mirrors EmailNotifier interface
    # ------------------------------------------------------------------

    def send_alert(self, events: list[CrashEvent]) -> bool:
        """Send an immediate WhatsApp alert for critical/warning events."""
        if not self._enabled or not events:
            return False

        critical = [e for e in events if e.severity == Severity.CRITICAL]
        warnings = [e for e in events if e.severity == Severity.WARNING]

        # Build compact plain-text message
        lines: list[str] = []

        if critical:
            lines.append(f"🚨 *AutopsyGuard ALERTA CRÍTICO*")
        else:
            lines.append(f"⚠️ *AutopsyGuard Aviso*")

        lines.append(f"📅 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        lines.append(f"Crítico(s): {len(critical)} | Aviso(s): {len(warnings)}")
        lines.append("")

        # List events (limit to first 5 to avoid message too long)
        for event in events[:5]:
            severity_icon = "🔴" if event.severity == Severity.CRITICAL else "🟡"
            lines.append(f"{severity_icon} {event.crash_type.name}: {event.message[:100]}")

        if len(events) > 5:
            lines.append(f"... e mais {len(events) - 5} evento(s)")

        lines.append("")
        lines.append("Verifique o email para detalhes completos.")

        message = "\n".join(lines)
        return self._send_message(message)

    def send_report(
        self,
        system_status: str,
        events_last_period: int,
        metrics_samples: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Send a periodic WhatsApp status summary."""
        if not self._enabled:
            return False

        uptime = self.get_uptime()

        if events_last_period == 0:
            status_icon = "✅"
            status_text = "Tudo OK"
        else:
            status_icon = "⚠️"
            status_text = f"{events_last_period} evento(s)"

        lines = [
            f"📊 *AutopsyGuard Relatório*",
            f"📅 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            "",
            f"{status_icon} Estado: {status_text}",
            f"⏱️ Uptime: {uptime}",
            f"📈 Eventos no período: {events_last_period}",
        ]

        # Add basic metrics if available
        if metrics_samples and len(metrics_samples) > 0:
            latest = metrics_samples[-1]
            cpu = latest.get("cpu_percent")
            mem = latest.get("memory_percent")
            if cpu is not None:
                lines.append(f"💻 CPU: {cpu:.1f}%")
            if mem is not None:
                lines.append(f"🧠 RAM: {mem:.1f}%")

        lines.append("")
        lines.append("Detalhes completos enviados por email.")

        message = "\n".join(lines)
        return self._send_message(message)

    def send_ingest_report(self, duration_seconds: float) -> bool:
        """Send a report when an Autopsy ingest job finishes."""
        if not self._enabled:
            return False

        hours, rem = divmod(int(duration_seconds), 3600)
        minutes, seconds = divmod(rem, 60)
        duration_str = f"{hours}h {minutes}m {seconds}s"

        lines = [
            f"🏁 *AutopsyGuard - Ingestão Concluída*",
            f"O processo de ingestão no Autopsy terminou com sucesso.",
            f"",
            f"⏱️ *Tempo Total:* {duration_str}"
        ]

        message = "\n".join(lines)
        return self._send_message(message)

    # ------------------------------------------------------------------
    # Internal: HTTP dispatch
    # ------------------------------------------------------------------

    def _send_message(self, text: str) -> bool:
        """Send a message via CallMeBot webhook. Retries up to 3 times."""

        def _do_send() -> bool:
            params = urllib.parse.urlencode({
                "phone": self.config.whatsapp_phone,
                "text": text,
                "apikey": self.config.whatsapp_apikey,
            })
            url = f"{_CALLMEBOT_URL}?{params}"

            max_attempts = 3
            base_backoff = 2.0
            last_exc: Exception | None = None

            for attempt in range(1, max_attempts + 1):
                try:
                    logger.debug(
                        "WhatsApp send attempt %d/%d", attempt, max_attempts
                    )
                    req = urllib.request.Request(url, method="GET")
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        status = resp.status
                        if status == 200:
                            logger.info("📱 WhatsApp message sent successfully")
                            return True
                        else:
                            logger.warning(
                                "WhatsApp API returned status %d (attempt %d)",
                                status, attempt,
                            )
                except Exception as e:
                    last_exc = e
                    logger.warning(
                        "WhatsApp send failed (attempt %d/%d): %s",
                        attempt, max_attempts, e,
                    )

                if attempt < max_attempts:
                    backoff = base_backoff * (2 ** (attempt - 1))
                    time.sleep(backoff)

            logger.error(
                "❌ WhatsApp message failed after %d attempts: %s",
                max_attempts, last_exc,
            )
            return False

        # Send in a background thread to avoid blocking the monitor loop
        thread = threading.Thread(target=_do_send, daemon=True)
        thread.start()
        return True
