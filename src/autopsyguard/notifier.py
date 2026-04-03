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


# ═══════════════════════════════════════════════════════════════════════════════
# HTML Email Templates
# ═══════════════════════════════════════════════════════════════════════════════

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0; padding:0; background-color:#f4f4f7; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color:#f4f4f7;">
        <tr>
            <td align="center" style="padding: 30px 10px;">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="background-color:#ffffff; border-radius:8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow:hidden;">
                    <!-- Header -->
                    <tr>
                        <td style="background: linear-gradient(135deg, {header_color_start} 0%, {header_color_end} 100%); padding: 30px 40px; text-align:center;">
                            <div style="font-size: 36px; margin-bottom: 10px;">{header_icon}</div>
                            <h1 style="color:#ffffff; margin:0; font-size:24px; font-weight:600; letter-spacing:-0.5px;">{header_title}</h1>
                            <p style="color:rgba(255,255,255,0.9); margin:8px 0 0 0; font-size:14px;">{header_subtitle}</p>
                        </td>
                    </tr>
                    
                    <!-- Timestamp bar -->
                    <tr>
                        <td style="background-color:#f8f9fa; padding:12px 40px; border-bottom:1px solid #e9ecef;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td style="font-size:13px; color:#6c757d;">
                                        📅 {timestamp}
                                    </td>
                                    <td align="right" style="font-size:13px; color:#6c757d;">
                                        {case_name}
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Body content -->
                    <tr>
                        <td style="padding: 30px 40px;">
                            {body_content}
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background-color:#f8f9fa; padding:20px 40px; border-top:1px solid #e9ecef;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td style="font-size:12px; color:#868e96;">
                                        <strong>AutopsyGuard</strong> — Sistema de Monitorização Forense
                                    </td>
                                    <td align="right" style="font-size:12px; color:#868e96;">
                                        v1.0.0
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
                
                <!-- Footer note -->
                <p style="color:#868e96; font-size:11px; margin-top:20px; text-align:center;">
                    Este é um email automático. Não responda a esta mensagem.
                </p>
            </td>
        </tr>
    </table>
</body>
</html>
"""

ALERT_EVENT_ROW = """
<tr>
    <td style="padding: 12px 16px; border-bottom: 1px solid #f1f3f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr>
                <td width="50" valign="top">
                    <div style="width:40px; height:40px; border-radius:8px; background-color:{icon_bg}; text-align:center; line-height:40px; font-size:18px;">
                        {icon}
                    </div>
                </td>
                <td style="padding-left:12px;">
                    <div style="font-size:12px; font-weight:600; color:{severity_color}; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">
                        {severity} — {crash_type}
                    </div>
                    <div style="font-size:14px; color:#2d3436; line-height:1.4;">
                        {message}
                    </div>
                </td>
            </tr>
        </table>
    </td>
</tr>
"""

STATUS_CARD = """
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:20px;">
    <tr>
        <td style="background: linear-gradient(135deg, {bg_start} 0%, {bg_end} 100%); border-radius:8px; padding:20px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                    <td width="60" valign="top">
                        <div style="font-size:32px;">{icon}</div>
                    </td>
                    <td style="padding-left:12px;">
                        <div style="font-size:12px; color:rgba(255,255,255,0.8); text-transform:uppercase; letter-spacing:1px; margin-bottom:4px;">
                            {label}
                        </div>
                        <div style="font-size:24px; font-weight:600; color:#ffffff;">
                            {value}
                        </div>
                    </td>
                </tr>
            </table>
        </td>
    </tr>
</table>
"""


def _get_event_icon(crash_type: str) -> tuple[str, str]:
    """Return icon and background color for crash type."""
    icons = {
        "JVM_CRASH": ("💥", "#fee2e2"),
        "HANG": ("⏳", "#fef3c7"),
        "PROCESS_DISAPPEARED": ("👻", "#e0e7ff"),
        "SOLR_CRASH": ("🔍", "#fce7f3"),
        "HIGH_RESOURCE_USAGE": ("📊", "#dbeafe"),
        "LOG_ERROR": ("📝", "#f3e8ff"),
        "OOM": ("🧠", "#fee2e2"),
        "ABNORMAL_EXIT": ("🚪", "#fed7aa"),
    }
    return icons.get(crash_type, ("⚠️", "#f3f4f6"))


def _get_severity_color(severity: Severity) -> str:
    """Return color for severity level."""
    return {
        Severity.CRITICAL: "#dc2626",
        Severity.WARNING: "#d97706",
        Severity.INFO: "#2563eb",
    }.get(severity, "#6b7280")


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
        warning_count = sum(1 for e in events if e.severity == Severity.WARNING)
        
        # Subject line
        if critical_count > 0:
            subject = f"🚨 [AutopsyGuard] CRÍTICO: {critical_count} problema(s) detetado(s)"
        else:
            subject = f"⚠️ [AutopsyGuard] Aviso: {warning_count} anomalia(s) detetada(s)"

        # Build event rows
        event_rows = ""
        for event in events:
            icon, icon_bg = _get_event_icon(event.crash_type.name)
            severity_color = _get_severity_color(event.severity)
            
            event_rows += ALERT_EVENT_ROW.format(
                icon=icon,
                icon_bg=icon_bg,
                severity=event.severity.name,
                severity_color=severity_color,
                crash_type=event.crash_type.name.replace("_", " "),
                message=event.message,
            )

        # Summary section
        summary = f"""
        <div style="margin-bottom:24px;">
            <p style="color:#4b5563; font-size:15px; line-height:1.6; margin:0 0 16px 0;">
                O sistema de monitorização detetou <strong>{len(events)} evento(s)</strong> que requerem a sua atenção.
            </p>
            <table role="presentation" cellspacing="0" cellpadding="0" style="margin-bottom:8px;">
                <tr>
                    <td style="background-color:#dc2626; color:white; padding:4px 12px; border-radius:4px; font-size:13px; font-weight:600;">
                        {critical_count} Crítico(s)
                    </td>
                    <td width="8"></td>
                    <td style="background-color:#d97706; color:white; padding:4px 12px; border-radius:4px; font-size:13px; font-weight:600;">
                        {warning_count} Aviso(s)
                    </td>
                </tr>
            </table>
        </div>
        """

        # Events table
        body_content = summary + f"""
        <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                    <td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                        <strong style="color:#374151; font-size:14px;">Eventos Detetados</strong>
                    </td>
                </tr>
                {event_rows}
            </table>
        </div>
        
        <div style="margin-top:24px; padding:16px; background-color:#fef3c7; border-radius:8px; border-left:4px solid #d97706;">
            <p style="color:#92400e; font-size:13px; margin:0;">
                <strong>💡 Recomendação:</strong> Verifique o estado do Autopsy e os logs do sistema para mais detalhes sobre estes eventos.
            </p>
        </div>
        """

        # Build full HTML
        case_name = self.config.case_dir.name if self.config.case_dir else "N/A"
        html_body = BASE_TEMPLATE.format(
            header_color_start="#dc2626" if critical_count > 0 else "#d97706",
            header_color_end="#991b1b" if critical_count > 0 else "#b45309",
            header_icon="🚨" if critical_count > 0 else "⚠️",
            header_title="Alerta de Sistema",
            header_subtitle="Foram detetadas anomalias que requerem atenção",
            timestamp=datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
            case_name=f"📁 {case_name}",
            body_content=body_content,
        )

        return self._dispatch_email(subject, html_body)

    def send_report(self, system_status: str, events_last_period: int) -> bool:
        """Send a periodic heartbeat report to assure the user the system is running."""
        if not self._enabled:
            return False

        subject = "📊 [AutopsyGuard] Relatório de Status"
        
        # Status card
        if events_last_period == 0:
            status_icon = "✅"
            status_text = "Tudo OK"
            status_bg_start = "#10b981"
            status_bg_end = "#059669"
        else:
            status_icon = "⚠️"
            status_text = f"{events_last_period} Evento(s)"
            status_bg_start = "#f59e0b"
            status_bg_end = "#d97706"

        status_card = STATUS_CARD.format(
            bg_start=status_bg_start,
            bg_end=status_bg_end,
            icon=status_icon,
            label="Estado do Sistema",
            value=status_text,
        )

        # System info
        body_content = f"""
        {status_card}
        
        <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                    <td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                        <strong style="color:#374151; font-size:14px;">📋 Detalhes da Monitorização</strong>
                    </td>
                </tr>
                <tr>
                    <td style="padding:16px;">
                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                            <tr>
                                <td style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#6b7280; font-size:13px;">Estado Atual</span>
                                </td>
                                <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#111827; font-size:13px; font-weight:500;">{system_status}</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#6b7280; font-size:13px;">Eventos no Último Período</span>
                                </td>
                                <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#111827; font-size:13px; font-weight:500;">{events_last_period}</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#6b7280; font-size:13px;">Intervalo de Polling</span>
                                </td>
                                <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#111827; font-size:13px; font-weight:500;">{self.config.poll_interval}s</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:8px 0;">
                                    <span style="color:#6b7280; font-size:13px;">Timeout de Hang</span>
                                </td>
                                <td align="right" style="padding:8px 0;">
                                    <span style="color:#111827; font-size:13px; font-weight:500;">{self.config.hang_timeout}s</span>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </div>
        
        <div style="padding:16px; background-color:#eff6ff; border-radius:8px; border-left:4px solid #3b82f6;">
            <p style="color:#1e40af; font-size:13px; margin:0;">
                <strong>ℹ️ Info:</strong> Este relatório é enviado periodicamente para confirmar que o sistema de monitorização está ativo.
            </p>
        </div>
        """

        # Build full HTML
        case_name = self.config.case_dir.name if self.config.case_dir else "N/A"
        html_body = BASE_TEMPLATE.format(
            header_color_start="#3b82f6",
            header_color_end="#1d4ed8",
            header_icon="📊",
            header_title="Relatório de Status",
            header_subtitle="Resumo periódico do sistema de monitorização",
            timestamp=datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
            case_name=f"📁 {case_name}",
            body_content=body_content,
        )

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
            logger.debug("A conectar ao servidor SMTP %s:%d...", 
                        self.config.smtp_host, self.config.smtp_port)
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                server.ehlo()
                if server.has_extn('STARTTLS'):
                    server.starttls()
                    server.ehlo()
                if self.config.smtp_password:
                    server.login(self.config.smtp_user, self.config.smtp_password)
                server.send_message(msg)
                
            logger.info("📧 Email enviado: %s", subject[:60])
            return True
        except (smtplib.SMTPException, OSError, TimeoutError) as e:
            logger.error("❌ Falha ao enviar email: %s", e)
            return False
