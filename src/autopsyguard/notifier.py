"""Notification system for AutopsyGuard.

Handles dispatching alerts and periodic status reports via various channels.
Initially implemented: SMTP Email notifications.
"""

from __future__ import annotations

import logging
import time
import smtplib
import psutil
from pathlib import Path
import base64
import hashlib
import csv
import io
import json
from email.message import EmailMessage
from datetime import datetime, timedelta
from typing import Any

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, Severity
from autopsyguard.utils.metrics_chart import render_system_chart_png

logger = logging.getLogger(__name__)

# Track when AutopsyGuard started for uptime calculation
_start_time: datetime | None = None

def set_start_time() -> None:
    """Set the start time for uptime tracking. Call once at startup."""
    global _start_time
    _start_time = datetime.now()

def get_uptime() -> str:
    """Get formatted uptime string."""
    if _start_time is None:
        return "N/A"
    delta = datetime.now() - _start_time
    hours, remainder = divmod(int(delta.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


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
                    <div style="font-size:14px; color:#2d3436; line-height:1.4; margin-bottom:8px;">
                        {message}
                    </div>
                    {details_html}
                </td>
            </tr>
        </table>
    </td>
</tr>
"""

DETAIL_ROW = """
<div style="font-size:12px; color:#6b7280; background-color:#f9fafb; padding:8px 10px; border-radius:4px; margin-top:6px; font-family:monospace; word-break:break-all;">
    <strong>{key}:</strong> {value}
</div>
"""

METRIC_BOX = """
<td style="text-align:center; padding:12px;">
    <div style="font-size:24px; margin-bottom:4px;">{icon}</div>
    <div style="font-size:20px; font-weight:600; color:{color};">{value}</div>
    <div style="font-size:11px; color:#6b7280; text-transform:uppercase;">{label}</div>
</td>
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
        "OUT_OF_MEMORY": ("🧠", "#fee2e2"),
        "ABNORMAL_EXIT": ("🚪", "#fed7aa"),
        "ZOMBIE": ("🧟", "#e0e7ff"),
    }
    return icons.get(crash_type, ("⚠️", "#f3f4f6"))


def _get_severity_color(severity: Severity) -> str:
    """Return color for severity level."""
    return {
        Severity.CRITICAL: "#dc2626",
        Severity.WARNING: "#d97706",
        Severity.INFO: "#2563eb",
    }.get(severity, "#6b7280")


def _format_details(details: dict[str, Any] | None) -> str:
    """Format event details dict into HTML rows."""
    if not details:
        return ""
    html_parts = []

    # Priority order for display
    priority_keys = [
        "log_line", "log_file", "pid", "exit_code", "error",
        "cpu_percent", "cores_used", "cpu_per_core_percent", "cpu_count",
        "memory_percent", "duration_seconds", "duration", "crash_summary"
    ]

    # User-friendly labels
    labels = {
        "log_line": "📋 Log",
        "log_file": "📁 Ficheiro",
        "pid": "🔢 PID",
        "exit_code": "⚠️ Exit Code",
        "error": "❌ Erro",
        "cpu_percent": "💻 CPU",
        "cores_used": "⚙️ Núcleos usados",
        "cpu_per_core_percent": "📊 % por núcleo",
        "cpu_count": "🔢 Núcleos (totais)",
        "memory_percent": "🧠 Memória",
        "duration": "⏱️ Duração",
        "duration_seconds": "⏱️ Duração",
        "crash_summary": "💥 Resumo",
        "core_name": "📦 Core",
        "timeout_seconds": "⏰ Timeout",
        "elapsed": "⏱️ Tempo",
    }

    def _fmt_value(k: str, v: Any) -> str:
        if v is None:
            return "N/A"
        # Numbers: format with sensible units/precision
        if isinstance(v, float):
            if k in ("cpu_percent", "cpu_per_core_percent", "memory_percent", "disk_percent", "usage_percent"):
                return f"{v:.1f}%"
            if k in ("cores_used",):
                return f"{v:.1f}"
            if k in ("duration_seconds", "elapsed"):
                return f"{v:.0f}s"
            if k.endswith("_gb") or k in ("memory_used_gb", "memory_total_gb", "disk_free_gb", "disk_total_gb"):
                return f"{v:.1f} GB"
            if k.endswith("_bytes"):
                # show MB for readability
                return f"{v / (1024**2):.1f} MB"
            return f"{v}"
        if isinstance(v, int):
            if k in ("pid", "exit_code", "cpu_count"):
                return str(v)
            return str(v)
        # Fallback for other types
        s = str(v)
        if len(s) > 200:
            s = s[:200] + "..."
        return s

    # Show priority keys first, then others
    shown_keys = set()
    for key in priority_keys:
        if key in details:
            value = details[key]
            label = labels.get(key, key.replace("_", " ").title())
            html_parts.append(DETAIL_ROW.format(key=label, value=_fmt_value(key, value)))
            shown_keys.add(key)

    # Show remaining keys
    for key, value in details.items():
        if key not in shown_keys:
            label = labels.get(key, key.replace("_", " ").title())
            html_parts.append(DETAIL_ROW.format(key=label, value=_fmt_value(key, value)))

    return "".join(html_parts)


def _short_event_id(event: CrashEvent) -> str:
    """Return a short 8-char hex id for an event based on timestamp and message."""
    h = hashlib.sha1()
    seed = f"{event.timestamp.isoformat()}|{event.crash_type.value}|{event.message}"
    h.update(seed.encode("utf-8"))
    return h.hexdigest()[:8]


def _suggestion_for_event(event: CrashEvent) -> str:
    """Return a very brief suggestion in Portuguese for common event types."""
    t = event.crash_type
    if t.name == "HANG":
        return "Verifique CPU/RAM e logs; considere reiniciar o processo Autopsy se necessário."
    if t.name == "JVM_CRASH":
        return "Rever o ficheiro hs_err_pid; reiniciar Autopsy e recolher heap/core."
    if t.name == "OUT_OF_MEMORY":
        return "Analisar uso de memória; aumentar heap do Solr/Java ou reduzir carga."
    if t.name == "PROCESS_DISAPPEARED":
        return "Confirmar se o processo foi terminado; verificar logs e sistema de operacional."
    if t.name == "HIGH_RESOURCE_USAGE":
        return "Identificar processos consumidores; considerar limitar ou reiniciar."
    if t.name == "SOLR_CRASH":
        return "Verificar saúde do Solr, arquivos de log e configuração de heap."
    if t.name == "LOG_ERROR":
        return "Investigar mensagens de erro no ficheiro de logs indicado."
    return "Verificar logs e estado do sistema para mais detalhes."


def _get_system_metrics(case_dir: Path | None = None) -> dict[str, Any]:
    """Get current system metrics.

    Prefer disk usage of the monitored `case_dir` when available; fall back
    to the system root partition otherwise.
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        # Determine disk path: prefer the case directory's mount if provided
        if case_dir is not None and case_dir.exists():
            disk_path = str(case_dir)
        else:
            disk_path = "/" if not psutil.WINDOWS else "C:\\"
        disk = psutil.disk_usage(disk_path)
        cpu_count = psutil.cpu_count(logical=True) or 1
        # Convert aggregate percent into approximate cores used
        cpu_cores_used = (cpu_percent / 100.0) * cpu_count

        return {
            "cpu_percent": cpu_percent,
            "cpu_count": cpu_count,
            "cpu_cores_used": cpu_cores_used,
            "memory_percent": memory.percent,
            "memory_used_gb": memory.used / (1024**3),
            "memory_total_gb": memory.total / (1024**3),
            "disk_free_gb": disk.free / (1024**3),
            "disk_total_gb": disk.total / (1024**3),
            "disk_percent": disk.percent,
        }
    except Exception as e:
        logger.debug("Failed to get system metrics: %s", e)
        return {}


def _get_autopsy_pid() -> int | None:
    """Find Autopsy process PID."""
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            name = proc.info['name'].lower()
            if 'autopsy' in name and 'java' not in name:
                return proc.info['pid']
    except Exception:
        pass
    return None


class EmailNotifier:
    """Sends HTML email alerts using Python's built-in smtplib."""

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self._enabled = bool(
            self.config.smtp_host and 
            self.config.email_recipient
        )
        self._event_history: list[tuple[datetime, CrashEvent]] = []
        self._max_history = 50  # Keep last 50 events

    def is_enabled(self) -> bool:
        """Check if the email notifier has the minimum necessary configuration to run."""
        return self._enabled
    
    def record_event(self, event: CrashEvent) -> None:
        """Record an event for history tracking."""
        self._event_history.append((datetime.now(), event))
        # Trim old events
        if len(self._event_history) > self._max_history:
            self._event_history = self._event_history[-self._max_history:]
    
    def get_recent_events(self, hours: float = 1.0) -> list[tuple[datetime, CrashEvent]]:
        """Get events from the last N hours."""
        cutoff = datetime.now() - timedelta(hours=hours)
        return [(ts, ev) for ts, ev in self._event_history if ts >= cutoff]

    def send_alert(self, events: list[CrashEvent]) -> bool:
        """Send an immediate alert for critical/warning events."""
        if not self._enabled or not events:
            return False

        # Record events for history
        for event in events:
            self.record_event(event)

        critical_count = sum(1 for e in events if e.severity == Severity.CRITICAL)
        warning_count = sum(1 for e in events if e.severity == Severity.WARNING)
        
        # Subject line
        if critical_count > 0:
            subject = f"🚨 [AutopsyGuard] CRÍTICO: {critical_count} problema(s) detetado(s)"
        else:
            subject = f"⚠️ [AutopsyGuard] Aviso: {warning_count} anomalia(s) detetada(s)"

        # Build event rows with details
        event_rows = ""
        for event in events:
            icon, icon_bg = _get_event_icon(event.crash_type.name)
            severity_color = _get_severity_color(event.severity)
            details_html = _format_details(event.details)
            
            event_rows += ALERT_EVENT_ROW.format(
                icon=icon,
                icon_bg=icon_bg,
                severity=event.severity.name,
                severity_color=severity_color,
                crash_type=event.crash_type.name.replace("_", " "),
                message=event.message,
                details_html=details_html,
            )

        # Get current system state (prefer case_dir for disk stats)
        metrics = _get_system_metrics(self.config.case_dir)
        autopsy_pid = _get_autopsy_pid()

        # System metrics bar
        metrics_html = ""
        if metrics:
            cpu_color = "#dc2626" if metrics.get("cpu_percent", 0) > 80 else "#10b981"
            mem_color = "#dc2626" if metrics.get("memory_percent", 0) > 85 else "#10b981"
            disk_color = "#dc2626" if metrics.get("disk_free_gb", 100) < 5 else "#10b981"

            # Compose CPU display with cores used when available
            cpu_pct = metrics.get("cpu_percent", 0)
            cpu_count = metrics.get("cpu_count")
            if cpu_count:
                cores_used = metrics.get("cpu_cores_used", 0.0)
                # Compact single-line representation to save space in the metric box
                cpu_display = f"{cpu_pct:.1f}% • {cores_used:.1f}/{cpu_count} núcleos"
            else:
                cpu_display = f"{cpu_pct:.1f}%"

            metrics_html = f"""
            <div style="margin-bottom:20px; padding:16px; background-color:#f8f9fa; border-radius:8px;">
                <div style="font-size:12px; color:#6b7280; margin-bottom:12px; text-transform:uppercase; letter-spacing:1px;">
                    📊 Estado do Sistema no Momento do Alerta
                </div>
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                    <tr>
                        {METRIC_BOX.format(icon="💻", value=cpu_display, label="CPU", color=cpu_color)}
                        {METRIC_BOX.format(icon="🧠", value=f"{metrics.get('memory_percent', 0):.1f}%", label="Memória", color=mem_color)}
                        {METRIC_BOX.format(icon="💾", value=f"{metrics.get('disk_free_gb', 0):.1f}GB", label="Disco Livre", color=disk_color)}
                        {METRIC_BOX.format(icon="🔍", value=str(autopsy_pid or 'N/A'), label="Autopsy PID", color="#3b82f6")}
                    </tr>
                </table>
                    <div style="font-size:11px; color:#6b7280; margin-top:8px;">
                        Nota: 'Process %' pode exceder 100% — conta núcleos usados.
                    </div>
                </div>
            """
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
        body_content = metrics_html + summary + f"""
        <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                    <td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                        <strong style="color:#374151; font-size:14px;">📋 Eventos Detetados</strong>
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
        
        <div style="margin-top:12px; padding:12px 16px; background-color:#f3f4f6; border-radius:8px;">
            <p style="color:#6b7280; font-size:12px; margin:0;">
                📁 <strong>Logs:</strong> {self.config.case_dir / "Log" if self.config.case_dir else "N/A"}
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

        # Plain-text fallback summary with short event IDs and brief suggestions
        plain_lines = [subject, "", f"Crítico(s): {critical_count}", f"Aviso(s): {warning_count}", f"Uptime: {get_uptime()}"]
        plain_lines.append("")
        # List up to first 10 events with short id, severity and suggestion
        for ev in events[:10]:
            eid = _short_event_id(ev)
            suggestion = _suggestion_for_event(ev)
            plain_lines.append(f"[{eid}] {ev.severity.name}: {ev.message}")
            plain_lines.append(f"    Sugestão: {suggestion}")
        plain_lines.append("")
        plain_lines.append("Nota: 'Process %' pode exceder 100% — conta núcleos usados.")
        plain_text = "\n".join(plain_lines)

        return self._dispatch_email(subject, html_body, plain_text=plain_text)

    def send_report(
        self,
        system_status: str,
        events_last_period: int,
        metrics_samples: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Send a periodic heartbeat report to assure the user the system is running."""
        if not self._enabled:
            return False

        subject = "📊 [AutopsyGuard] Relatório de Status"
        
        # Get system metrics and autopsy info (prefer case_dir for disk stats)
        metrics = _get_system_metrics(self.config.case_dir)
        autopsy_pid = _get_autopsy_pid()
        uptime = get_uptime()
        recent_events = self.get_recent_events(self.config.report_interval_hours)
        
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

        # System metrics bar
        metrics_html = ""
        if metrics:
            cpu_color = "#dc2626" if metrics.get("cpu_percent", 0) > 80 else "#10b981"
            mem_color = "#dc2626" if metrics.get("memory_percent", 0) > 85 else "#10b981"
            disk_color = "#dc2626" if metrics.get("disk_free_gb", 100) < 5 else "#10b981"

            cpu_pct = metrics.get("cpu_percent", 0)
            cpu_count = metrics.get("cpu_count")
            if cpu_count:
                cores_used = metrics.get("cpu_cores_used", 0.0)
                # Compact single-line representation to save space in the metric box
                cpu_display = f"{cpu_pct:.1f}% • {cores_used:.1f}/{cpu_count} núcleos"
            else:
                cpu_display = f"{cpu_pct:.1f}%"

            metrics_html = f"""
            <div style="margin-bottom:20px; padding:16px; background-color:#f8f9fa; border-radius:8px;">
                <div style="font-size:12px; color:#6b7280; margin-bottom:12px; text-transform:uppercase; letter-spacing:1px;">
                    📊 Recursos do Sistema
                </div>
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                    <tr>
                        {METRIC_BOX.format(icon="💻", value=cpu_display, label="CPU", color=cpu_color)}
                        {METRIC_BOX.format(icon="🧠", value=f"{metrics.get('memory_percent', 0):.1f}%", label="Memória", color=mem_color)}
                        {METRIC_BOX.format(icon="💾", value=f"{metrics.get('disk_free_gb', 0):.1f}GB", label="Disco Livre", color=disk_color)}
                    </tr>
                </table>
                <div style="font-size:11px; color:#6b7280; margin-top:8px;">
                    Nota: 'Process %' pode exceder 100% — conta núcleos usados.
                </div>
            </div>
            """

        chart_html = ""
        inline_images: list[tuple[str, bytes, str]] = []
        # Build alert windows from recent events (use duration if present)
        alert_windows: list[tuple[float, float]] = []
        for ts, ev in recent_events:
            try:
                dur = float(ev.details.get("duration_seconds") or ev.details.get("duration") or 0)
            except Exception:
                dur = 0.0
            end_ts = ts.timestamp()
            start_ts = end_ts - dur if dur > 0 else end_ts
            alert_windows.append((start_ts, end_ts))

        if metrics_samples:
            chart_png = render_system_chart_png(metrics_samples, alert_windows=alert_windows)
            if chart_png:
                # Attach as inline image (Content-ID) for clients that support it
                inline_images.append(("system_chart", chart_png, "png"))

                # ALSO embed as a data URI fallback so web previews and browsers
                # that don't resolve cid: URLs can still render the chart.
                b64 = base64.b64encode(chart_png).decode("ascii")
                # Use Outlook conditional comments: show the CID image only to MSO (Outlook),
                # and show the data-URI image to other clients. This avoids displaying a
                # broken icon + duplicate image in clients that can't resolve cid: URLs.
                chart_html = f"""
                <div style="margin-bottom:20px;">
                    <div style="font-size:12px; color:#6b7280; margin-bottom:8px; text-transform:uppercase; letter-spacing:1px;">
                        📈 Tendências de Sistema (desde o último email)
                    </div>
                    <!--[if mso]>
                        <img src="cid:system_chart" alt="System chart" style="width:100%; max-width:520px; border-radius:8px; border:1px solid #e5e7eb; display:block;">
                    <![endif]-->
                    <!--[if !mso]><!-- -->
                        <img src="data:image/png;base64,{b64}" alt="System chart" style="width:100%; max-width:520px; border-radius:8px; border:1px solid #e5e7eb; display:block;">
                    <!--<![endif]-->
                </div>
                """

        # Recent events section
        recent_events_html = ""
        if recent_events:
            event_rows = ""
            for ts, event in recent_events[-10:]:  # Show last 10
                icon, icon_bg = _get_event_icon(event.crash_type.name)
                severity_color = _get_severity_color(event.severity)
                event_rows += f"""
                <tr>
                    <td style="padding:8px 12px; border-bottom:1px solid #f3f4f6; font-size:12px; color:#6b7280;">
                        {ts.strftime("%H:%M:%S")}
                    </td>
                    <td style="padding:8px 12px; border-bottom:1px solid #f3f4f6;">
                        <span style="font-size:14px;">{icon}</span>
                    </td>
                    <td style="padding:8px 12px; border-bottom:1px solid #f3f4f6; font-size:12px; color:{severity_color}; font-weight:600;">
                        {event.severity.name}
                    </td>
                    <td style="padding:8px 12px; border-bottom:1px solid #f3f4f6; font-size:12px; color:#374151;">
                        {event.message[:50]}{'...' if len(event.message) > 50 else ''}
                    </td>
                </tr>
                """
            recent_events_html = f"""
            <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                    <tr>
                        <td style="background-color:#fef3c7; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                            <strong style="color:#92400e; font-size:14px;">⚠️ Eventos Recentes ({len(recent_events)})</strong>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:0;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                {event_rows}
                            </table>
                        </td>
                    </tr>
                </table>
            </div>
            """

        # System info
        body_content = f"""
        {status_card}
        {metrics_html}
        {chart_html}
        {recent_events_html}
        
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
                                    <span style="color:#6b7280; font-size:13px;">🔍 Autopsy PID</span>
                                </td>
                                <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#111827; font-size:13px; font-weight:500;">{autopsy_pid or 'Não detetado'}</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#6b7280; font-size:13px;">⏱️ Uptime AutopsyGuard</span>
                                </td>
                                <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#111827; font-size:13px; font-weight:500;">{uptime}</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#6b7280; font-size:13px;">📊 Estado Atual</span>
                                </td>
                                <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#111827; font-size:13px; font-weight:500;">{system_status}</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#6b7280; font-size:13px;">📈 Eventos no Período</span>
                                </td>
                                <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#111827; font-size:13px; font-weight:500;">{events_last_period}</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#6b7280; font-size:13px;">⏲️ Intervalo de Polling</span>
                                </td>
                                <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;">
                                    <span style="color:#111827; font-size:13px; font-weight:500;">{self.config.poll_interval}s</span>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding:8px 0;">
                                    <span style="color:#6b7280; font-size:13px;">⏰ Timeout de Hang</span>
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

        # Prepare attachments with raw metrics (CSV + JSON) for offline analysis
        attachments: list[tuple[str, bytes, str]] = []
        try:
            # JSON
            json_b = json.dumps(metrics_samples, default=str, ensure_ascii=False, indent=2).encode("utf-8")
            attachments.append(("metrics.json", json_b, "application/json"))

            # CSV: derive header from union of keys in samples
            if metrics_samples:
                fieldnames = []
                seen = set()
                for s in metrics_samples:
                    for k in s.keys():
                        if k not in seen:
                            seen.add(k)
                            fieldnames.append(k)
                sio = io.StringIO()
                writer = csv.DictWriter(sio, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for row in metrics_samples:
                    # Coerce non-serializable values to strings
                    safe_row = {k: (v if isinstance(v, (str, int, float, bool)) or v is None else str(v)) for k, v in row.items()}
                    writer.writerow(safe_row)
                csv_b = sio.getvalue().encode("utf-8")
                attachments.append(("metrics.csv", csv_b, "text/csv"))
        except Exception:
            attachments = []

        # Plain-text fallback summary for reports
        plain_lines = [subject, "", f"Estado: {status_text}", f"Eventos no período: {events_last_period}", f"Uptime: {uptime}", f"Autopsy PID: {autopsy_pid or 'N/A'}"]
        if metrics_samples:
            plain_lines.append("Inclui anexos: metrics.csv, metrics.json")
        plain_lines.append("")
        # Include brief recent events summary with short IDs and suggestions
        if recent_events:
            plain_lines.append("Eventos recentes:")
            for ts, ev in recent_events[-10:]:
                eid = _short_event_id(ev)
                suggestion = _suggestion_for_event(ev)
                plain_lines.append(f"[{eid}] {ts.strftime('%Y-%m-%d %H:%M:%S')} {ev.severity.name}: {ev.message}")
                plain_lines.append(f"    Sugestão: {suggestion}")
            plain_lines.append("")

        plain_lines.append("Nota: 'Process %' pode exceder 100% — conta núcleos usados.")
        plain_text = "\n".join(plain_lines)

        return self._dispatch_email(subject, html_body, inline_images=inline_images, attachments=attachments, plain_text=plain_text)

    def _dispatch_email(
        self,
        subject: str,
        html_body: str,
        *,
        inline_images: list[tuple[str, bytes, str]] | None = None,
        attachments: list[tuple[str, bytes, str]] | None = None,
        plain_text: str | None = None,
    ) -> bool:
        """Core function that constructs the MIME and talks to the SMTP server."""
        msg = EmailMessage()
        if plain_text:
            msg.set_content(plain_text)
        else:
            msg.set_content("O seu cliente de e-mail não suporta HTML. Por favor use um cliente moderno.")
        msg.add_alternative(html_body, subtype='html')

        if inline_images:
            # Prefer to get the HTML body via EmailMessage API; fall back to iterating parts.
            html_part = None
            try:
                html_part = msg.get_body(preferencelist=("html",))
            except Exception:
                html_part = None

            if html_part is None:
                for part in msg.iter_parts():
                    if part.get_content_type() == "text/html":
                        html_part = part
                        break

            if html_part is not None:
                for cid, data, subtype in inline_images:
                    # Email Content-ID headers should be enclosed in angle brackets.
                    try:
                        html_part.add_related(data, maintype="image", subtype=subtype, cid=f"<{cid}>")
                    except Exception:
                        # Some EmailMessage parts may not support add_related; skip gracefully
                        logger.debug("Could not add related image %s", cid)
            else:
                logger.debug("No HTML body found to attach inline images; skipping related images")

        # Add binary/text attachments (CSV/JSON etc.)
        if attachments:
            for filename, data, mime in attachments:
                try:
                    maintype, subtype = mime.split('/', 1)
                except Exception:
                    maintype, subtype = 'application', 'octet-stream'
                msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
        
        msg['Subject'] = subject
        msg['From'] = self.config.email_sender
        msg['To'] = self.config.email_recipient

        # Send with retry/backoff
        max_attempts = 3
        base_backoff = 1.0
        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                logger.debug("Connecting to SMTP %s:%d (attempt %d)", self.config.smtp_host, self.config.smtp_port, attempt)
                with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=30) as server:
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
                last_exc = e
                logger.warning("Falha ao enviar email (attempt %d/%d): %s", attempt, max_attempts, e)
                if attempt < max_attempts:
                    backoff = base_backoff * (2 ** (attempt - 1))
                    logger.debug("Aguardando %.1fs antes da próxima tentativa...", backoff)
                    time.sleep(backoff)

        logger.error("❌ Falha ao enviar email após %d tentativas: %s", max_attempts, last_exc)
        return False
