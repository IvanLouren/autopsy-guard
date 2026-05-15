"""Builds the HTML body and attachments for periodic heartbeat reports.

Separated from the EmailNotifier dispatch class to keep each file focused on
a single concern: this module only knows how to *compose* report content; it
does not send anything.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Any

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent
from autopsyguard.platform_utils import get_case_log_file
from autopsyguard.utils.metrics_chart import render_system_chart_png
from autopsyguard.notifiers.email.templates import (
    BASE_TEMPLATE,
    METRIC_BOX,
    STATUS_CARD,
    RESOURCE_THRESHOLDS,
    get_case_label,
    get_event_icon,
    get_severity_color,
    get_system_metrics,
    short_event_id,
    suggestion_for_event,
)

logger = logging.getLogger(__name__)


def build_report_email(
    config: MonitorConfig,
    system_status: str,
    events_last_period: int,
    uptime: str,
    recent_events: list[tuple[datetime, CrashEvent]],
    metrics_samples: list[dict[str, Any]] | None,
    autopsy_pid: int | None,
) -> tuple[str, str, list[tuple[str, bytes, str]], list[tuple[str, bytes, str]]]:
    """Compose a full heartbeat report email.

    Returns ``(subject, html_body, inline_images, attachments)``.
    """
    case_label = get_case_label(config)
    subject = f"📊 [AutopsyGuard] Relatório de Status - {case_label}"
    metrics = get_system_metrics(config.case_dir)

    # --- Status card ---
    if events_last_period == 0:
        status_icon, status_text = "✅", "Tudo OK"
        status_bg_start, status_bg_end = "#10b981", "#059669"
    else:
        status_icon = "⚠️"
        status_text = f"{events_last_period} Evento(s)"
        status_bg_start, status_bg_end = "#f59e0b", "#d97706"

    status_card = STATUS_CARD.format(
        bg_start=status_bg_start,
        bg_end=status_bg_end,
        icon=status_icon,
        label="Estado do Sistema",
        value=status_text,
    )

    # --- System metrics bar ---
    metrics_html = _build_metrics_bar(metrics)

    # --- Chart ---
    chart_html, inline_images = _build_chart(metrics_samples, recent_events)

    # --- Recent events table ---
    recent_events_html = _build_recent_events_table(recent_events)

    # --- Monitoring details table ---
    details_table = _build_details_table(config, system_status, events_last_period, uptime, autopsy_pid)

    # --- Case artifacts section ---
    case_artifacts_html, case_artifacts_plain = _build_case_artifacts_section(config)

    body_content = (
        status_card
        + metrics_html
        + chart_html
        + recent_events_html
        + details_table
        + case_artifacts_html
        + """
        <div style="padding:16px; background-color:#eff6ff; border-radius:8px; border-left:4px solid #3b82f6;">
            <p style="color:#1e40af; font-size:13px; margin:0;">
                <strong>ℹ️ Info:</strong> Este relatório é enviado periodicamente para confirmar que o sistema de monitorização está ativo.
            </p>
        </div>
        """
    )

    case_label = get_case_label(config)
    html_body = BASE_TEMPLATE.format(
        header_color_start="#3b82f6",
        header_color_end="#1d4ed8",
        header_icon="📊",
        header_title="Relatório de Status",
        header_subtitle="Resumo periódico do sistema de monitorização",
        timestamp=datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
        case_name=f"📁 {case_label}",
        body_content=body_content,
    )

    # --- Attachments (CSV + JSON) ---
    attachments = _build_attachments(metrics_samples)

    # --- Plain-text fallback ---
    plain_text = _build_plain_text(
        subject, status_text, events_last_period, uptime,
        autopsy_pid, metrics_samples, recent_events,
        case_artifacts_plain,
    )

    return subject, html_body, plain_text, inline_images, attachments


# ---------------------------------------------------------------------------
# Private composition helpers
# ---------------------------------------------------------------------------

def _build_metrics_bar(metrics: dict[str, Any]) -> str:
    if not metrics:
        return ""
    cpu_color = "#dc2626" if metrics.get("cpu_percent", 0) > RESOURCE_THRESHOLDS["cpu_warn"] else "#10b981"
    mem_color = "#dc2626" if metrics.get("memory_percent", 0) > RESOURCE_THRESHOLDS["mem_warn"] else "#10b981"
    disk_color = "#dc2626" if metrics.get("disk_free_gb", 100) < RESOURCE_THRESHOLDS["disk_warn_gb"] else "#10b981"

    cpu_pct = metrics.get("cpu_percent", 0)
    cpu_count = metrics.get("cpu_count")
    if cpu_count:
        cores_used = metrics.get("cpu_cores_used", 0.0)
        cpu_display = f"{cpu_pct:.1f}% • {cores_used:.1f}/{cpu_count} núcleos"
    else:
        cpu_display = f"{cpu_pct:.1f}%"

    return f"""
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


def _build_chart(
    metrics_samples: list[dict[str, Any]] | None,
    recent_events: list[tuple[datetime, CrashEvent]],
) -> tuple[str, list[tuple[str, bytes, str]]]:
    inline_images: list[tuple[str, bytes, str]] = []
    if not metrics_samples:
        return "", inline_images

    alert_windows: list[tuple[float, float]] = []
    for ts, ev in recent_events:
        try:
            dur = float(ev.details.get("duration_seconds") or ev.details.get("duration") or 0)
        except Exception:
            dur = 0.0
        end_ts = ts.timestamp()
        alert_windows.append((end_ts - dur if dur > 0 else end_ts, end_ts))

    chart_png = render_system_chart_png(metrics_samples, alert_windows=alert_windows)
    if not chart_png:
        return "", inline_images

    inline_images.append(("system_chart", chart_png, "png"))
    chart_html = f"""
    <div style="margin-bottom:20px;">
        <div style="font-size:12px; color:#6b7280; margin-bottom:8px; text-transform:uppercase; letter-spacing:1px;">
            📈 Tendências de Sistema (desde o último email)
        </div>
        <img src="cid:system_chart" alt="System chart" style="width:100%; max-width:520px; border-radius:8px; border:1px solid #e5e7eb; display:block;">
    </div>
    """
    return chart_html, inline_images


def _build_recent_events_table(recent_events: list[tuple[datetime, CrashEvent]]) -> str:
    if not recent_events:
        return ""
    rows = ""
    for ts, event in recent_events[-10:]:
        icon, _ = get_event_icon(event.crash_type.name)
        severity_color = get_severity_color(event.severity)
        rows += f"""
        <tr>
            <td style="padding:8px 12px; border-bottom:1px solid #f3f4f6; font-size:12px; color:#6b7280;">{ts.strftime("%H:%M:%S")}</td>
            <td style="padding:8px 12px; border-bottom:1px solid #f3f4f6;"><span style="font-size:14px;">{icon}</span></td>
            <td style="padding:8px 12px; border-bottom:1px solid #f3f4f6; font-size:12px; color:{severity_color}; font-weight:600;">{event.severity.name}</td>
            <td style="padding:8px 12px; border-bottom:1px solid #f3f4f6; font-size:12px; color:#374151;">{event.message[:50]}{'...' if len(event.message) > 50 else ''}</td>
        </tr>
        """
    return f"""
    <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr><td style="background-color:#fef3c7; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                <strong style="color:#92400e; font-size:14px;">⚠️ Eventos Recentes ({len(recent_events)})</strong>
            </td></tr>
            <tr><td style="padding:0;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">{rows}</table>
            </td></tr>
        </table>
    </div>
    """


def _build_details_table(
    config: MonitorConfig,
    system_status: str,
    events_last_period: int,
    uptime: str,
    autopsy_pid: int | None,
) -> str:
    def _row(label: str, value: str) -> str:
        return f"""
        <tr>
            <td style="padding:8px 0; border-bottom:1px solid #f3f4f6;"><span style="color:#6b7280; font-size:13px;">{label}</span></td>
            <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;"><span style="color:#111827; font-size:13px; font-weight:500;">{value}</span></td>
        </tr>
        """
    rows = (
        _row("🔍 Autopsy PID", str(autopsy_pid or "Não detetado"))
        + _row("⏱️ Uptime AutopsyGuard", uptime)
        + _row("📊 Estado Atual", system_status)
        + _row("📈 Eventos no Período", str(events_last_period))
        + _row("⏲️ Intervalo de Polling", f"{config.poll_interval}s")
        + _row("⏰ Timeout de Hang", f"{config.hang_timeout}s")
    )
    return f"""
    <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr><td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                <strong style="color:#374151; font-size:14px;">📋 Detalhes da Monitorização</strong>
            </td></tr>
            <tr><td style="padding:16px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">{rows}</table>
            </td></tr>
        </table>
    </div>
    """


def _build_case_artifacts_section(config: MonitorConfig) -> tuple[str, list[str]]:
    case_dir = config.case_dir
    db_path = case_dir / "autopsy.db"
    log_path = get_case_log_file(case_dir)

    rows: list[str] = []
    plain_lines: list[str] = []

    def _row(label: str, value: str) -> str:
        return f"""
        <tr>
            <td style="padding:8px 0; border-bottom:1px solid #f3f4f6;"><span style="color:#6b7280; font-size:13px;">{label}</span></td>
            <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;"><span style="color:#111827; font-size:13px; font-weight:500;">{value}</span></td>
        </tr>
        """

    def _fmt_size(size_bytes: int | None) -> str:
        if size_bytes is None:
            return "N/A"
        size = float(size_bytes)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024.0 or unit == "TB":
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def _fmt_time(path: Path) -> str:
        try:
            return datetime.fromtimestamp(path.stat().st_mtime).strftime("%d/%m/%Y %H:%M:%S")
        except OSError:
            return "N/A"

    def _count_lines(path: Path) -> int | None:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                return sum(1 for _ in handle)
        except OSError:
            return None

    def _path_summary(path: Path, *, include_lines: bool = False) -> tuple[str, str]:
        if not path.exists():
            return "Não encontrado", "Não encontrado"
        try:
            stat = path.stat()
        except OSError:
            return "Indisponível", "Indisponível"
        value = f"{_fmt_size(stat.st_size)} | Atualizado: {_fmt_time(path)}"
        if include_lines:
            line_count = _count_lines(path)
            value += f" | Linhas: {line_count if line_count is not None else 'N/A'}"
        return value, value

    db_value_html, db_value_plain = _path_summary(db_path)
    log_value_html, log_value_plain = _path_summary(log_path, include_lines=True)

    rows.append(_row("🗄️ Base de dados do caso (autopsy.db)", db_value_html))
    rows.append(_row("📝 Log corrente do Autopsy (autopsy.log.0)", log_value_html))
    plain_lines.append(f"autopsy.db: {db_value_plain}")
    plain_lines.append(f"autopsy.log.0: {log_value_plain}")

    module_dirs = _discover_module_directories(case_dir)
    if module_dirs:
        rows.append(
            _row(
                f"📁 Pastas de módulos ({len(module_dirs)})",
                "Ver secção abaixo",
            )
        )
        module_rows = "".join(
            _row(
                entry[0],
                f"{_fmt_size(entry[1])} | Atualizado: {entry[2]}",
            )
            for entry in module_dirs
        )
        rows_html = module_rows
    else:
        rows_html = ""

    section = f"""
    <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr><td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                <strong style="color:#374151; font-size:14px;">📂 Estado do Caso e Artefactos</strong>
            </td></tr>
            <tr><td style="padding:16px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">{''.join(rows)}</table>
                {f'<div style="margin-top:14px; font-size:12px; color:#6b7280; text-transform:uppercase; letter-spacing:1px;">📁 Pastas de módulos</div><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:8px;">{rows_html}</table>' if rows_html else ''}
            </td></tr>
        </table>
    </div>
    """
    if module_dirs:
        plain_lines.append("Pastas de módulos:")
        for name, size_bytes, updated in module_dirs:
            plain_lines.append(f"  - {name}: {_fmt_size(size_bytes)} | Atualizado: {updated}")

    return section, plain_lines


def _discover_module_directories(case_dir: Path) -> list[tuple[str, int, str]]:
    entries: list[tuple[str, int, str]] = []
    ignored = {"Log", ".autopsyguard", "__pycache__"}
    try:
        for child in case_dir.iterdir():
            if not child.is_dir() or child.name in ignored or child.name.startswith("."):
                continue
            size_bytes = 0
            latest_mtime: float | None = None
            try:
                for file_path in child.rglob("*"):
                    if not file_path.is_file():
                        continue
                    try:
                        stat = file_path.stat()
                    except OSError:
                        continue
                    size_bytes += int(stat.st_size)
                    if latest_mtime is None or stat.st_mtime > latest_mtime:
                        latest_mtime = stat.st_mtime
            except OSError:
                continue
            if latest_mtime is None:
                continue
            entries.append((child.name, size_bytes, datetime.fromtimestamp(latest_mtime).strftime("%d/%m/%Y %H:%M:%S")))
    except OSError:
        return []
    entries.sort(key=lambda item: item[2], reverse=True)
    return entries[:10]


def _build_attachments(
    metrics_samples: list[dict[str, Any]] | None,
) -> list[tuple[str, bytes, str]]:
    if not metrics_samples:
        return []
    try:
        attachments: list[tuple[str, bytes, str]] = []
        json_b = json.dumps(metrics_samples, default=str, ensure_ascii=False, indent=2).encode("utf-8")
        attachments.append(("metrics.json", json_b, "application/json"))

        fieldnames: list[str] = []
        seen: set[str] = set()
        for s in metrics_samples:
            for k in s:
                if k not in seen:
                    seen.add(k)
                    fieldnames.append(k)
        sio = io.StringIO()
        writer = csv.DictWriter(sio, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in metrics_samples:
            safe = {k: (v if isinstance(v, (str, int, float, bool)) or v is None else str(v)) for k, v in row.items()}
            writer.writerow(safe)
        attachments.append(("metrics.csv", sio.getvalue().encode("utf-8"), "text/csv"))
        return attachments
    except Exception:
        return []


def _build_plain_text(
    subject: str,
    status_text: str,
    events_last_period: int,
    uptime: str,
    autopsy_pid: int | None,
    metrics_samples: list[dict[str, Any]] | None,
    recent_events: list[tuple[datetime, CrashEvent]],
    case_artifacts_lines: list[str] | None,
) -> str:
    lines = [
        subject, "",
        f"Estado: {status_text}",
        f"Eventos no período: {events_last_period}",
        f"Uptime: {uptime}",
        f"Autopsy PID: {autopsy_pid or 'N/A'}",
    ]
    if metrics_samples:
        lines.append("Inclui anexos: metrics.csv, metrics.json")
    if case_artifacts_lines:
        lines.append("")
        lines.append("Estado do caso e artefactos:")
        lines.extend(case_artifacts_lines)
    lines.append("")
    if recent_events:
        lines.append("Eventos recentes:")
        for ts, ev in recent_events[-10:]:
            eid = short_event_id(ev)
            hint = suggestion_for_event(ev)
            lines.append(f"[{eid}] {ts.strftime('%Y-%m-%d %H:%M:%S')} {ev.severity.name}: {ev.message}")
            lines.append(f"    Sugestão: {hint}")
        lines.append("")
    lines.append("Nota: 'Process %' pode exceder 100% — conta núcleos usados.")
    return "\n".join(lines)
