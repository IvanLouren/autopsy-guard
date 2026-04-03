"""Notification system for AutopsyGuard.

Handles dispatching alerts and periodic status reports via various channels.
Initially implemented: SMTP Email notifications.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from datetime import datetime

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, Severity

logger = logging.getLogger(__name__)


class EmailNotifier:
    """Sends HTML email alerts using Python's built-in smtplib."""

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self._enabled = bool(
            self.config.smtp_host and 
            self.config.smtp_user and 
            self.config.email_recipient
        )

    def is_enabled(self) -> bool:
        """Check if the email notifier has the minimum necessary configuration to run."""
        return self._enabled

    def send_alert(self, events: list[CrashEvent]) -> bool:
        """Send an immediate alert for critical/warning events."""
        if not self._enabled or not events:
            return False

        critical_count = sum(1 for e in events if e.severity == Severity.CRITICAL)
        subject = f"[AutopsyGuard] Alerta: {len(events)} anomalias detetadas ({critical_count} CRÍTICAS)"

        # Build HTML Body
        html_body = "<h2>🚨 AutopsyGuard: Alerta de Sistema 🚨</h2>"
        html_body += f"<p>Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
        html_body += "<ul>"
        
        for event in events:
            color = "red" if event.severity == Severity.CRITICAL else "orange"
            html_body += f"<li><b style='color:{color}'>[{event.severity.name}] {event.crash_type.name}</b>: {event.message}</li>"
            
        html_body += "</ul>"

        return self._dispatch_email(subject, html_body)

    def send_report(self, system_status: str, events_last_period: int) -> bool:
        """Send a periodic heartbeat report to assure the user the system is running."""
        if not self._enabled:
            return False

        subject = "[AutopsyGuard] Relatório Periódico de Status"
        
        html_body = "<h2>📊 AutopsyGuard: Relatório de Monitorização 📊</h2>"
        html_body += f"<p>Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"
        html_body += "<h3>Estado Atual</h3>"
        html_body += f"<p>{system_status}</p>"
        html_body += f"<p>Eventos (alertas) gerados no último ciclo: {events_last_period}</p>"
        
        html_body += "<hr><p><small>Este é um e-mail automático gerado pelo sistema de telemetria AutopsyGuard.</small></p>"

        return self._dispatch_email(subject, html_body)

    def _dispatch_email(self, subject: str, html_body: str) -> bool:
        """Core function that constructs the MIME and talks to the SMTP server."""
        msg = EmailMessage()
        msg.set_content("O seu cliente de e-mail não suporta HTML. Por favor use um cliente moderno.")
        msg.add_alternative(html_body, subtype='html')
        
        msg['Subject'] = subject
        msg['From'] = self.config.email_sender
        msg['To'] = self.config.email_recipient

        try:
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                server.ehlo()
                if server.has_extn('STARTTLS'):
                    server.starttls()
                    server.ehlo()
                if self.config.smtp_password:
                    server.login(self.config.smtp_user, self.config.smtp_password)
                server.send_message(msg)
                
            logger.info("📧 Email enviado: %s", subject[:50])
            return True
        except (smtplib.SMTPException, OSError, TimeoutError) as e:
            logger.error("❌ Falha ao enviar email: %s", e)
            return False
