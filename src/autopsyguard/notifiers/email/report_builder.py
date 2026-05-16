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
from autopsyguard.utils.messages import tr
from autopsyguard.utils.case_telemetry import collect_case_telemetry
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
    subject = f"📊 [AutopsyGuard] {tr(config, 'report_subject')} - {get_case_label(config)}"
    metrics = get_system_metrics(config.case_dir)
    telemetry_data = telemetry or collect_case_telemetry(
        config=config,
        solr_status=None,
        solr_metrics=None,
        cpu_snapshots={0.0: None, 300.0: None, 900.0: None},
    )

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
    telemetry_html = _build_telemetry_sections(config, telemetry_data)

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
        telemetry_data,
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
                {METRIC_BOX.format(icon="🧠", value=f"{metrics.get('memory_percent', 0):.1f}%", label=tr(config, "memory"), color=mem_color)}
                {METRIC_BOX.format(icon="🗄️", value=f"{metrics.get('disk_free_gb', 0):.1f}GB", label=tr(config, "disk_free"), color=disk_color)}
            </tr>
        </table>
        <div style="font-size:11px; color:#6b7280; margin-top:8px;">
            {tr(config, "metric_note_multicore")}
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
            <tr><td style="padding:16px;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0">{rows}</table></td></tr>
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
    mod_activity_summary = telemetry.get("module_activity_summary", []) or []
    mod_activity = telemetry.get("module_activity", []) or []
    if not mod_activity_summary and mod_activity:
        mod_activity_summary = [
            {
                "module_name": item.get("module", "N/A"),
                "last_state": item.get("state", "active"),
                "last_seen": item.get("timestamp"),
                "error_count": item.get("error_count", 0),
                "occurrence_count": item.get("occurrence_count", 1),
                "sample_last_line": item.get("line", ""),
                "confidence": item.get("confidence", "stale"),
            }
            for item in mod_activity
        ]
    module_errors_summary = telemetry.get("module_errors_summary", []) or []
    latest_activity = _pick_recent_activity(
        [
            {
                "module": item.get("module_name", item.get("module", "N/A")),
                "state": item.get("last_state", "active"),
                "timestamp": item.get("last_seen"),
                "occurrence_count": item.get("occurrence_count"),
                "activity_events": item.get("activity_events"),
                "error_count": item.get("error_count"),
                "confidence": item.get("confidence"),
                "line": item.get("sample_last_line", ""),
            }
            for item in mod_activity_summary
        ]
    )
    log_updated_at = log.get("updated_at") or tr(config, "none")
    now_dt = datetime.now()

    def _activity_ts(item: dict[str, Any]) -> str:
        ts = item.get("timestamp")
        if ts:
            return str(ts)
        return str(log_updated_at)

    module_confidence = _activity_confidence_label(latest_activity, log_updated_at)
    module_age = _age_label(_activity_ts(latest_activity), now_dt)
    module_errors = int(latest_activity.get("error_count") or latest_activity.get("error_events") or 0)
    module_activity_events = int(latest_activity.get("activity_events") or latest_activity.get("occurrence_count") or 0)
    latest_module_line = (
        f"{latest_activity.get('module', tr(config, 'none'))} | "
        f"{latest_activity.get('state', tr(config, 'none'))} | "
        f"{_activity_ts(latest_activity)} | {module_age} | "
        f"confidence={module_confidence} | errors={module_errors} | activity={module_activity_events}"
    )

    db_line = (
        tr(config, "db_missing")
        if not db.get("exists")
        else f"{_bytes_to_human(db.get('size_bytes'))} | {db.get('updated_at') or 'N/A'}"
    )
    log_line = (
        "N/A"
        if not log.get("exists")
        else (
            f"{_bytes_to_human(log.get('size_bytes'))} | "
            f"{log.get('updated_at') or 'N/A'} | "
            f"{tr(config, 'lines_label')}={log.get('line_count', 0)} | "
            f"{_age_label(log.get('updated_at'), now_dt)}"
        )
    )
    case_size = _bytes_to_human(telemetry.get("case_size_bytes"))
    solr_raw_state = str(solr.get("state", "unknown")).lower()
    solr_rt = _format_optional_float(solr.get("response_time_seconds"), suffix="s")
    solr_heap = _format_optional_float(solr.get("heap_usage_percent"), suffix="%")
    solr_cpu = _format_optional_float(solr.get("cpu_percent"), suffix="%")
    solr_error = str(solr.get("error") or "").strip() or tr(config, "none")
    solr_checked_at = solr.get("checked_at") or tr(config, "none")
    context = ""
    error_label = tr(config, "last_error")
    solr_state = tr(config, "none")
    if solr_raw_state == "down":
        solr_state = tr(config, "solr_down")
        err_low = solr_error.lower()
        if any(token in err_low for token in ("connection", "refused", "forcibly", "reset", "timed out", "timeout")):
            context = tr(config, "solr_context_outage")
        elif "http 4" in err_low:
            context = tr(config, "solr_context_transient")
        else:
            context = tr(config, "solr_context_outage")
    elif solr_raw_state == "up":
        rt_val = _coerce_float(solr.get("response_time_seconds"))
        slow_threshold = max(0.0, float(getattr(config, "solr_slow_threshold_seconds", 2.0)))
        if solr.get("error"):
            solr_state = "UP_WITH_WARNING"
            context = tr(config, "solr_context_up_warning")
            error_label = tr(config, "last_warning")
        elif rt_val is not None and rt_val > slow_threshold:
            solr_state = "DEGRADED"
            context = "Solr is reachable but response latency is elevated."
        else:
            solr_state = tr(config, "solr_up")

    solr_line = (
        f"{solr_state} | rt={solr_rt} | "
        f"heap={solr_heap} | cpu={solr_cpu} | "
        f"{tr(config, 'checked_at')}={solr_checked_at} | {error_label}={solr_error}"
    )
    if context:
        solr_line += f" | {context}"

    cpu_now = cpu_tl.get("current")
    cpu_5m = cpu_tl.get("minus_5m")
    cpu_15m = cpu_tl.get("minus_15m")
    cpu_cores_now = (cpu_now / 100.0) if cpu_now is not None else None
    cpu_cores_5m = (cpu_5m / 100.0) if cpu_5m is not None else None
    cpu_cores_15m = (cpu_15m / 100.0) if cpu_15m is not None else None

    def _cpu_sample_label(label: str, cpu_value: float | None, core_value: float | None) -> str:
        if cpu_value is None:
            return f"{label}: N/A"
        if core_value is None:
            return f"{label}: {cpu_value:.1f}%"
        return f"{label}: {cpu_value:.1f}% ({core_value:.1f} cores)"

    cpu_line = (
        f"{_cpu_sample_label(tr(config, 'cpu_now'), cpu_now, cpu_cores_now)} | "
        f"{_cpu_sample_label(tr(config, 'cpu_5m'), cpu_5m, cpu_cores_5m)} | "
        f"{_cpu_sample_label(tr(config, 'cpu_15m'), cpu_15m, cpu_cores_15m)}"
    )

    module_rows = ""
    for m in modules[:10]:
        module_rows += _row(
            f"📂 {m.get('name', 'N/A')}",
            f"{_bytes_to_human(m.get('size_bytes'))} | {m.get('updated_at') or 'N/A'}",
        )
    if not module_rows:
        module_rows = _row("📂 N/A", "N/A")

    keyword_solr_items = [
        item
        for item in mod_activity_summary
        if "keyword" in str(item.get("module_name", item.get("module", ""))).lower()
        or "solr" in str(item.get("module_name", item.get("module", ""))).lower()
    ]
    keyword_solr_line = tr(config, "keyword_solr_none")
    if keyword_solr_items:
        item = _pick_recent_activity(
            [
                {
                    "module": i.get("module_name", i.get("module", "N/A")),
                    "state": i.get("last_state", "active"),
                    "timestamp": i.get("last_seen"),
                    "activity_events": i.get("activity_events"),
                    "occurrence_count": i.get("occurrence_count"),
                    "error_count": i.get("error_count"),
                    "error_events": i.get("error_events"),
                    "confidence": i.get("confidence"),
                }
                for i in keyword_solr_items
            ]
        )
        activity_events = int(item.get("activity_events") or item.get("occurrence_count") or 0)
        error_events = int(item.get("error_count") or item.get("error_events") or 0)
        keyword_age = _age_label(_activity_ts(item), now_dt)
        keyword_confidence = _activity_confidence_label(item, log_updated_at)
        keyword_solr_line = (
            f"{item.get('module', tr(config, 'none'))} | "
            f"{item.get('state', tr(config, 'none'))} | "
            f"{_activity_ts(item)} | {keyword_age} | confidence={keyword_confidence} | "
            f"errors={error_events} | activity={activity_events}"
        )

    module_errors_line = tr(config, "module_errors_none")
    if module_errors_summary:
        parts: list[str] = []
        for item in module_errors_summary[:3]:
            parts.append(
                f"{item.get('module', 'N/A')} ({item.get('signature', 'unknown')}): "
                f"occurrences={item.get('occurrence_count', 1)}, "
                f"first={item.get('first_seen') or 'N/A'}, "
                f"last={item.get('last_seen') or 'N/A'}"
            )
        module_errors_line = " ; ".join(parts)

    top = (
        _row("🗃️ " + tr(config, "db_title"), db_line)
        + _row("🧾 " + tr(config, "log_title"), log_line)
        + _row("🗄️ " + tr(config, "case_usage_title"), case_size)
        + _row("🧭 " + tr(config, "module_recent_title"), latest_module_line)
        + _row("🔎 " + tr(config, "keyword_solr_title"), keyword_solr_line)
        + _row("🧯 " + tr(config, "module_errors_summary_title"), module_errors_line)
        + _row("🔬 " + tr(config, "solr_title"), solr_line)
        + _row("🖥️ " + tr(config, "cpu_history_title"), cpu_line)
    )
    return f"""
    <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
            <tr><td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                <strong style="color:#374151; font-size:14px;">🧪 {tr(config, 'telemetry_title')}</strong>
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
    """


def _pick_recent_activity(mod_activity: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick the best summary candidate for the Current/Recent Module row."""
    if not mod_activity:
        return {}
    priority: dict[str, int] = {
        "error": 0,
        "warning": 1,
        "active": 2,
        "seen": 3,
        "start": 4,
        "finish": 5,
    }

    def _score(item: dict[str, Any]) -> tuple[float, int, int]:
        state = str(item.get("state", "")).lower()
        module = str(item.get("module", "")).strip().lower()
        ingest_penalty = 1 if module == "ingest" and state in {"start", "finish"} else 0
        ts = _parse_activity_ts(item.get("timestamp"))
        # Prefer freshest activity first; use state priority as tie-breaker.
        freshness = ts.timestamp() if ts else -1.0
        return (freshness, -priority.get(state, 9), -ingest_penalty)

    return max(mod_activity, key=_score)


def _coerce_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _format_optional_float(value: Any, *, suffix: str = "") -> str:
    numeric = _coerce_float(value)
    if numeric is None:
        return "N/A"
    if suffix == "s":
        return f"{numeric:.3f}{suffix}"
    return f"{numeric:.1f}{suffix}"


def _parse_activity_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except Exception:
            continue
    return None


def _activity_confidence_label(activity: dict[str, Any], fallback_ts: Any) -> str:
    ts = _parse_activity_ts(activity.get("timestamp")) or _parse_activity_ts(fallback_ts)
    if ts is None:
        return "stale"
    age_seconds = (datetime.now() - ts).total_seconds()
    if age_seconds <= 300:
        return "current"
    if age_seconds <= 1800:
        return "recent"
    return "stale"


def _age_label(value: Any, now_dt: datetime) -> str:
    ts = _parse_activity_ts(value)
    if ts is None:
        return "age=N/A"
    age_seconds = max(0, int((now_dt - ts).total_seconds()))
    if age_seconds < 60:
        return f"age={age_seconds}s"
    if age_seconds < 3600:
        return f"age={age_seconds // 60}m"
    if age_seconds < 86400:
        return f"age={age_seconds // 3600}h"
    return f"age={age_seconds // 86400}d"


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
        module_activity_summary = telemetry.get("module_activity_summary") or []
        module_activity = telemetry.get("module_activity") or []
        if not module_activity_summary and module_activity:
            module_activity_summary = [
                {
                    "module_name": item.get("module", "N/A"),
                    "last_state": item.get("state", "active"),
                    "last_seen": item.get("timestamp"),
                    "activity_events": item.get("activity_events"),
                    "occurrence_count": item.get("occurrence_count"),
                    "error_count": item.get("error_count"),
                    "error_events": item.get("error_events"),
                    "confidence": item.get("confidence"),
                }
                for item in module_activity
            ]
        now_dt = datetime.now()
        log_updated_at = log.get("updated_at") or tr(config, "none")
        latest_activity = _pick_recent_activity(
            [
                {
                    "module": item.get("module_name", item.get("module", "N/A")),
                    "state": item.get("last_state", "active"),
                    "timestamp": item.get("last_seen"),
                    "activity_events": item.get("activity_events"),
                    "occurrence_count": item.get("occurrence_count"),
                    "error_count": item.get("error_count"),
                    "error_events": item.get("error_events"),
                    "confidence": item.get("confidence"),
                }
                for item in module_activity_summary
            ]
        )
        module_confidence = _activity_confidence_label(latest_activity, log_updated_at)
        module_age = _age_label(latest_activity.get("timestamp"), now_dt)
        module_errors = int(latest_activity.get("error_count") or latest_activity.get("error_events") or 0)
        module_activity_events = int(latest_activity.get("activity_events") or latest_activity.get("occurrence_count") or 0)
        latest_module_line = (
            f"{latest_activity.get('module', tr(config, 'none'))} | "
            f"{latest_activity.get('state', tr(config, 'none'))} | "
            f"{latest_activity.get('timestamp') or log_updated_at} | {module_age} | "
            f"confidence={module_confidence} | errors={module_errors} | activity={module_activity_events}"
        )
        keyword_solr_items = [
            item
            for item in module_activity_summary
            if "keyword" in str(item.get("module_name", item.get("module", ""))).lower()
            or "solr" in str(item.get("module_name", item.get("module", ""))).lower()
        ]
        keyword_solr_line = tr(config, "keyword_solr_none")
        if keyword_solr_items:
            item = _pick_recent_activity(
                [
                    {
                        "module": i.get("module_name", i.get("module", "N/A")),
                        "state": i.get("last_state", "active"),
                        "timestamp": i.get("last_seen"),
                        "activity_events": i.get("activity_events"),
                        "occurrence_count": i.get("occurrence_count"),
                        "error_count": i.get("error_count"),
                        "error_events": i.get("error_events"),
                        "confidence": i.get("confidence"),
                    }
                    for i in keyword_solr_items
                ]
            )
            keyword_activity_events = int(item.get("activity_events") or item.get("occurrence_count") or 0)
            keyword_errors = int(item.get("error_count") or item.get("error_events") or 0)
            keyword_confidence = _activity_confidence_label(item, log_updated_at)
            keyword_age = _age_label(item.get("timestamp"), now_dt)
            keyword_solr_line = (
                f"{item.get('module', tr(config, 'none'))} | "
                f"{item.get('state', tr(config, 'none'))} | "
                f"{item.get('timestamp') or log_updated_at} | {keyword_age} | "
                f"confidence={keyword_confidence} | errors={keyword_errors} | activity={keyword_activity_events}"
            )

        lines.append(f"{tr(config, 'plain_db_line')}: {tr(config, 'plain_db_present') if db.get('exists') else tr(config, 'plain_db_missing')}")
        lines.append(f"{tr(config, 'plain_log_lines')}: {log.get('line_count', 'N/A')}")
        lines.append(f"{tr(config, 'module_recent_title')}: {latest_module_line}")
        lines.append(f"{tr(config, 'keyword_solr_title')}: {keyword_solr_line}")
        module_errors_summary = telemetry.get("module_errors_summary") or []
        if module_errors_summary:
            lines.append(f"{tr(config, 'module_errors_summary_title')}:")
            for item in module_errors_summary[:5]:
                lines.append(
                    "- "
                    f"{item.get('module', 'N/A')} ({item.get('signature', 'unknown')}), "
                    f"occurrences={item.get('occurrence_count', 1)}, "
                    f"first={item.get('first_seen') or 'N/A'}, "
                    f"last={item.get('last_seen') or 'N/A'}"
                )
        modules = telemetry.get("module_folders") or []
        if modules:
            lines.append(f"{tr(config, 'modules_title')}:")
            for item in modules[:10]:
                lines.append(
                    f"- {item.get('name', 'N/A')}: "
                    f"{_bytes_to_human(item.get('size_bytes'))}, {item.get('updated_at') or 'N/A'}"
                )
    if metrics_samples:
        lines.append(tr(config, "plain_includes_attachments"))
    lines.append("")
    if recent_events:
        lines.append(tr(config, "plain_recent_events"))
        for ts, ev in recent_events[-10:]:
            eid = short_event_id(ev)
            hint = suggestion_for_event(ev, config)
            lines.append(f"[{eid}] {ts.strftime('%Y-%m-%d %H:%M:%S')} {ev.severity.name}: {ev.message}")
            lines.append(f"    {tr(config, 'plain_hint')}: {hint}")
    return "\n".join(lines)


