"""Build periodic heartbeat email body + attachments."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent
from autopsyguard.notifiers.email.templates import (
    BASE_TEMPLATE,
    METRIC_BOX,
    STATUS_CARD,
    RESOURCE_THRESHOLDS,
    get_case_label,
    get_event_icon,
    get_severity_color,
    short_event_id,
    suggestion_for_event,
    get_system_metrics,
)
from autopsyguard.utils.i18n import resolve_language, tr
from autopsyguard.utils.metrics_chart import render_system_chart_png


def build_report_email(
    config: MonitorConfig,
    system_status: str,
    events_last_period: int,
    uptime: str,
    recent_events: list[tuple[datetime, CrashEvent]],
    metrics_samples: list[dict[str, Any]] | None,
    autopsy_pid: int | None,
    telemetry: dict[str, Any] | None = None,
) -> tuple[str, str, str, list[tuple[str, bytes, str]], list[tuple[str, bytes, str]]]:
    lang = resolve_language(config)
    subject = f"📊 [AutopsyGuard] {tr(config, 'report_subject')} - {get_case_label(config)}"
    metrics = get_system_metrics(config.case_dir)

    if events_last_period == 0:
        status_icon, status_text = "✅", tr(config, "all_ok")
        status_bg_start, status_bg_end = "#10b981", "#059669"
    else:
        status_icon = "⚠️"
        status_text = tr(config, "events_count", count=events_last_period)
        status_bg_start, status_bg_end = "#f59e0b", "#d97706"

    status_card = STATUS_CARD.format(
        bg_start=status_bg_start,
        bg_end=status_bg_end,
        icon=status_icon,
        label=tr(config, "system_status"),
        value=status_text,
    )

    metrics_html = _build_metrics_bar(config, metrics)
    chart_html, inline_images = _build_chart(config, metrics_samples, recent_events)
    recent_events_html = _build_recent_events_table(config, recent_events)
    details_table = _build_details_table(config, system_status, events_last_period, uptime, autopsy_pid)
    telemetry_html = _build_telemetry_sections(config, telemetry or {})

    body_content = (
        status_card
        + metrics_html
        + chart_html
        + telemetry_html
        + recent_events_html
        + details_table
        + f"""
        <div style="padding:16px; background-color:#eff6ff; border-radius:8px; border-left:4px solid #3b82f6;">
            <p style="color:#1e40af; font-size:13px; margin:0;">
                <strong>ℹ️ Info:</strong> {tr(config, "report_info")}
            </p>
        </div>
        """
    )

    case_label = get_case_label(config)
    html_body = BASE_TEMPLATE.format(
        header_color_start="#3b82f6",
        header_color_end="#1d4ed8",
        header_icon="📊",
        header_title=tr(config, "report_header_title"),
        header_subtitle=tr(config, "report_header_subtitle"),
        timestamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        case_name=f"📁 {case_label}",
        body_content=body_content,
        footer_system=tr(config, "footer_system"),
        auto_email_note=tr(config, "auto_email"),
    )

    attachments = _build_attachments(metrics_samples)
    plain_text = _build_plain_text(
        config,
        subject,
        status_text,
        events_last_period,
        uptime,
        autopsy_pid,
        metrics_samples,
        recent_events,
        telemetry or {},
    )

    return subject, html_body, plain_text, inline_images, attachments


def _build_metrics_bar(config: MonitorConfig, metrics: dict[str, Any]) -> str:
    if not metrics:
        return ""
    cpu_color = "#dc2626" if metrics.get("cpu_percent", 0) > RESOURCE_THRESHOLDS["cpu_warn"] else "#10b981"
    mem_color = "#dc2626" if metrics.get("memory_percent", 0) > RESOURCE_THRESHOLDS["mem_warn"] else "#10b981"
    disk_color = "#dc2626" if metrics.get("disk_free_gb", 100) < RESOURCE_THRESHOLDS["disk_warn_gb"] else "#10b981"
    cpu_pct = metrics.get("cpu_percent", 0)
    cpu_count = metrics.get("cpu_count")
    if cpu_count:
        cores_used = metrics.get("cpu_cores_used", 0.0)
        cpu_display = f"{cpu_pct:.1f}% • {cores_used:.1f}/{cpu_count}"
    else:
        cpu_display = f"{cpu_pct:.1f}%"
    return f"""
    <div style="margin-bottom:20px; padding:16px; background-color:#f8f9fa; border-radius:8px;">
        <div style="font-size:12px; color:#6b7280; margin-bottom:12px; text-transform:uppercase; letter-spacing:1px;">
            🖥️ {tr(config, "resources")}
        </div>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr>
                {METRIC_BOX.format(icon="🖥️", value=cpu_display, label=tr(config, "cpu"), color=cpu_color)}
                {METRIC_BOX.format(icon="📈", value=f"{metrics.get('memory_percent', 0):.1f}%", label=tr(config, "memory"), color=mem_color)}
                {METRIC_BOX.format(icon="🗄️", value=f"{metrics.get('disk_free_gb', 0):.1f}GB", label=tr(config, "disk_free"), color=disk_color)}
            </tr>
        </table>
        <div style="font-size:11px; color:#6b7280; margin-top:8px;">
            Note: Process CPU may exceed 100% on multi-core systems.
        </div>
    </div>
    """


def _build_chart(
    config: MonitorConfig,
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

    chart_png = render_system_chart_png(
        metrics_samples,
        alert_windows=alert_windows,
        language=resolve_language(config),
    )
    if not chart_png:
        return "", inline_images

    inline_images.append(("system_chart", chart_png, "png"))
    chart_html = f"""
    <div style="margin-bottom:20px;">
        <div style="font-size:12px; color:#6b7280; margin-bottom:8px; text-transform:uppercase; letter-spacing:1px;">
            📈 {tr(config, "chart_title")}
        </div>
        <img src="cid:system_chart" alt="System chart" style="width:100%; max-width:520px; border-radius:8px; border:1px solid #e5e7eb; display:block;">
    </div>
    """
    return chart_html, inline_images


def _build_recent_events_table(config: MonitorConfig, recent_events: list[tuple[datetime, CrashEvent]]) -> str:
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
            <td style="padding:8px 12px; border-bottom:1px solid #f3f4f6; font-size:12px; color:#374151;">{event.message[:70]}{'...' if len(event.message) > 70 else ''}</td>
        </tr>
        """
    return f"""
    <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr><td style="background-color:#fef3c7; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                <strong style="color:#92400e; font-size:14px;">⚠️ {tr(config, "recent_events", count=len(recent_events))}</strong>
            </td></tr>
            <tr><td style="padding:0;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">{rows}</table>
            </td></tr>
        </table>
    </div>
    """


def _row(label: str, value: str) -> str:
    return f"""
    <tr>
        <td style="padding:8px 0; border-bottom:1px solid #f3f4f6;"><span style="color:#6b7280; font-size:13px;">{label}</span></td>
        <td align="right" style="padding:8px 0; border-bottom:1px solid #f3f4f6;"><span style="color:#111827; font-size:13px; font-weight:500;">{value}</span></td>
    </tr>
    """


def _bytes_to_human(v: int | float | None) -> str:
    if v is None:
        return "N/A"
    value = float(v)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f}{unit}"
        value /= 1024.0
    return f"{value:.1f}TB"


def _build_details_table(
    config: MonitorConfig,
    system_status: str,
    events_last_period: int,
    uptime: str,
    autopsy_pid: int | None,
) -> str:
    rows = (
        _row("🔍 " + tr(config, "autopsy_pid"), str(autopsy_pid or "N/A"))
        + _row("⏱️ " + tr(config, "uptime"), uptime)
        + _row("📊 " + tr(config, "current_status"), system_status)
        + _row("📈 " + tr(config, "events_period"), str(events_last_period))
        + _row("⏲️ " + tr(config, "poll_interval"), f"{config.poll_interval}s")
        + _row("⏰ " + tr(config, "hang_timeout"), f"{config.hang_timeout}s")
    )
    return f"""
    <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr><td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                <strong style="color:#374151; font-size:14px;">📋 {tr(config, "monitor_details")}</strong>
            </td></tr>
            <tr><td style="padding:16px;">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0">{rows}</table>
            </td></tr>
        </table>
    </div>
    """


def _build_telemetry_sections(config: MonitorConfig, telemetry: dict[str, Any]) -> str:
    if not telemetry:
        return ""
    db = telemetry.get("autopsy_db", {})
    log = telemetry.get("autopsy_log", {})
    solr = telemetry.get("solr", {})
    cpu_tl = telemetry.get("autopsy_cpu_timeline", {})
    modules = telemetry.get("module_folders", []) or []
    mod_activity = telemetry.get("module_activity", []) or []

    db_line = (
        tr(config, "db_missing")
        if not db.get("exists")
        else f"{_bytes_to_human(db.get('size_bytes'))} | {db.get('updated_at') or 'N/A'}"
    )
    log_line = (
        "N/A"
        if not log.get("exists")
        else f"{_bytes_to_human(log.get('size_bytes'))} | {log.get('updated_at') or 'N/A'} | lines={log.get('line_count', 0)}"
    )
    case_size = _bytes_to_human(telemetry.get("case_size_bytes"))
    solr_state = tr(config, "solr_up") if solr.get("state") == "up" else tr(config, "solr_down")
    solr_line = (
        f"{solr_state} | rt={solr.get('response_time_seconds') or 'N/A'}s | "
        f"heap={solr.get('heap_usage_percent') or 'N/A'}% | cpu={solr.get('cpu_percent') or 'N/A'}%"
    )

    cpu_now = cpu_tl.get("current")
    cpu_5m = cpu_tl.get("minus_5m")
    cpu_15m = cpu_tl.get("minus_15m")
    cpu_line = (
        f"{tr(config, 'cpu_now')}: {f'{cpu_now:.1f}%' if cpu_now is not None else 'N/A'} | "
        f"{tr(config, 'cpu_5m')}: {f'{cpu_5m:.1f}%' if cpu_5m is not None else 'N/A'} | "
        f"{tr(config, 'cpu_15m')}: {f'{cpu_15m:.1f}%' if cpu_15m is not None else 'N/A'}"
    )

    module_rows = ""
    for m in modules[:10]:
        module_rows += _row(
            f"📂 {m.get('name', 'N/A')}",
            f"{_bytes_to_human(m.get('size_bytes'))} | {m.get('updated_at') or 'N/A'}",
        )
    if not module_rows:
        module_rows = _row("📂 N/A", "N/A")

    activity_rows = ""
    for item in mod_activity[:8]:
        activity_rows += _row(f"🔎 {item.get('module', 'N/A')}", f"{item.get('state', 'seen')} | {item.get('line', '')[:70]}")
    if not activity_rows:
        activity_rows = _row("🔎 N/A", "N/A")

    top = (
        _row("🗃️ " + tr(config, "db_title"), db_line)
        + _row("🧾 " + tr(config, "log_title"), log_line)
        + _row("🗄️ " + tr(config, "case_usage_title"), case_size)
        + _row("🔬 " + tr(config, "solr_title"), solr_line)
        + _row("🖥️ " + tr(config, "cpu_history_title"), cpu_line)
    )
    return f"""
    <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr><td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                <strong style="color:#374151; font-size:14px;">🧪 Telemetry</strong>
            </td></tr>
            <tr><td style="padding:16px;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0">{top}</table></td></tr>
        </table>
    </div>
    <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr><td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                <strong style="color:#374151; font-size:14px;">📂 {tr(config, "modules_title")}</strong>
            </td></tr>
            <tr><td style="padding:16px;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0">{module_rows}</table></td></tr>
        </table>
    </div>
    <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr><td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                <strong style="color:#374151; font-size:14px;">🧭 {tr(config, "module_activity_title")}</strong>
            </td></tr>
            <tr><td style="padding:16px;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0">{activity_rows}</table></td></tr>
        </table>
    </div>
    """


def _build_attachments(metrics_samples: list[dict[str, Any]] | None) -> list[tuple[str, bytes, str]]:
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
    config: MonitorConfig,
    subject: str,
    status_text: str,
    events_last_period: int,
    uptime: str,
    autopsy_pid: int | None,
    metrics_samples: list[dict[str, Any]] | None,
    recent_events: list[tuple[datetime, CrashEvent]],
    telemetry: dict[str, Any],
) -> str:
    lines = [
        subject,
        "",
        f"{tr(config, 'system_status')}: {status_text}",
        f"{tr(config, 'events_period')}: {events_last_period}",
        f"{tr(config, 'uptime')}: {uptime}",
        f"{tr(config, 'autopsy_pid')}: {autopsy_pid or 'N/A'}",
    ]
    if telemetry:
        db = telemetry.get("autopsy_db", {})
        log = telemetry.get("autopsy_log", {})
        lines.append(f"autopsy.db: {'present' if db.get('exists') else 'missing'}")
        lines.append(f"autopsy.log.0 lines: {log.get('line_count', 'N/A')}")
    if metrics_samples:
        lines.append("Includes attachments: metrics.csv, metrics.json")
    lines.append("")
    if recent_events:
        lines.append("Recent events:")
        for ts, ev in recent_events[-10:]:
            eid = short_event_id(ev)
            hint = suggestion_for_event(ev, config)
            lines.append(f"[{eid}] {ts.strftime('%Y-%m-%d %H:%M:%S')} {ev.severity.name}: {ev.message}")
            lines.append(f"    Hint: {hint}")
    return "\n".join(lines)
