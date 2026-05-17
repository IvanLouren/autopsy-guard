"""HTML email templates and formatting helpers for AutopsyGuard alerts/reports.

All string constants and pure-function helpers live here so the EmailNotifier
class stays focused on dispatch logic only.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import psutil

from autopsyguard.config import MonitorConfig
from autopsyguard.utils.case_metadata import read_autopsy_case_display_name
from autopsyguard.models import CrashEvent, Severity



# ---------------------------------------------------------------------------
# Display thresholds for colouring resource metrics in emails
# ---------------------------------------------------------------------------

RESOURCE_THRESHOLDS = {
    "cpu_warn": 80.0,
    "mem_warn": 85.0,
    "disk_warn_gb": 5.0,
}


# ---------------------------------------------------------------------------
# HTML template strings
# ---------------------------------------------------------------------------

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
                                        <strong>AutopsyGuard</strong> — {footer_system}
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
                    {auto_email_note}
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


# ---------------------------------------------------------------------------
# Pure helper functions
# ---------------------------------------------------------------------------

def get_case_label(config: MonitorConfig) -> str:
    """Return a human-friendly case label for emails.

    Uses ``config.email_case_label`` when set; otherwise reads the Autopsy
    case name from ``*.aut`` (DisplayName / Name), then the directory name.
    """
    if getattr(config, "email_case_label", None):
        return config.email_case_label.strip()
    source = (getattr(config, "case_name_source", "real") or "real").strip().lower()
    if source == "real":
        try:
            from_aut = read_autopsy_case_display_name(config.case_dir)
            if from_aut:
                return from_aut
            return config.case_dir.name
        except Exception:
            return "Case"
    try:
        path = config.case_dir.resolve().as_posix() if config.case_dir else ""
    except Exception:
        path = ""
    h = hashlib.sha1()
    h.update(path.encode("utf-8"))
    return f"Case #{h.hexdigest()[:4].upper()}"


def get_event_icon(crash_type: str) -> tuple[str, str]:
    """Return (icon, background_color) for a crash type name."""
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
        "CORRELATED_INCIDENT": ("🧩", "#dbeafe"),
    }
    return icons.get(crash_type, ("⚠️", "#f3f4f6"))


def get_severity_color(severity: Severity) -> str:
    """Return the hex colour string for a severity level."""
    return {
        Severity.CRITICAL: "#dc2626",
        Severity.WARNING: "#d97706",
        Severity.INFO: "#2563eb",
    }.get(severity, "#6b7280")


def format_details(details: dict[str, Any] | None) -> str:
    """Format an event ``details`` dict into HTML DETAIL_ROW snippets."""
    if not details:
        return ""

    priority_keys = [
        "log_line", "log_file", "pid", "exit_code", "error",
        "cpu_percent", "cores_used", "cpu_per_core_percent", "cpu_count",
        "memory_percent", "duration_seconds", "duration", "crash_summary",
    ]
    labels = {
        "log_line": "📋 Log",
        "log_file": "📁 File",
        "pid": "🔢 PID",
        "exit_code": "⚠️ Exit Code",
        "error": "❌ Error",
        "cpu_percent": "💻 CPU",
        "cores_used": "⚙️ Cores Used",
        "cpu_per_core_percent": "📊 Per-Core %",
        "cpu_count": "🔢 Cores (Total)",
        "memory_percent": "🧠 Memory",
        "duration": "⏱️ Duration",
        "duration_seconds": "⏱️ Duration",
        "crash_summary": "💥 Summary",
        "core_name": "📦 Core",
        "timeout_seconds": "⏰ Timeout",
        "elapsed": "⏱️ Elapsed",
    }

    def _fmt(k: str, v: Any) -> str:
        if v is None:
            return "N/A"
        if isinstance(v, float):
            if k in ("cpu_percent", "cpu_per_core_percent", "memory_percent",
                     "disk_percent", "usage_percent"):
                return f"{v:.1f}%"
            if k in ("cores_used",):
                return f"{v:.1f}"
            if k in ("duration_seconds", "elapsed"):
                return f"{v:.0f}s"
            if k.endswith("_gb") or k in ("memory_used_gb", "memory_total_gb",
                                           "disk_free_gb", "disk_total_gb"):
                return f"{v:.1f} GB"
            if k.endswith("_bytes"):
                return f"{v / (1024**2):.1f} MB"
            return str(v)
        if isinstance(v, int):
            return str(v)
        s = str(v)
        return s[:200] + "..." if len(s) > 200 else s

    html_parts: list[str] = []
    shown: set[str] = set()
    for key in priority_keys:
        if key in details:
            label = labels.get(key, key.replace("_", " ").title())
            html_parts.append(DETAIL_ROW.format(key=label, value=_fmt(key, details[key])))
            shown.add(key)
    for key, value in details.items():
        if key not in shown:
            label = labels.get(key, key.replace("_", " ").title())
            html_parts.append(DETAIL_ROW.format(key=label, value=_fmt(key, value)))
    return "".join(html_parts)


def short_event_id(event: CrashEvent) -> str:
    """Return an 8-char hex fingerprint for an event (for plain-text logs)."""
    h = hashlib.sha1()
    h.update(
        f"{event.timestamp.isoformat()}|{event.crash_type.value}|{event.message}"
        .encode("utf-8")
    )
    return h.hexdigest()[:8]


def suggestion_for_event(event: CrashEvent, config: MonitorConfig | None = None) -> str:
    """Return a brief remediation hint for common event types."""
    name = event.crash_type.name
    hints = {
        "HANG": "Check CPU/RAM and logs; consider restarting Autopsy if needed.",
        "JVM_CRASH": "Review hs_err_pid file; restart Autopsy and collect heap/core evidence.",
        "OUT_OF_MEMORY": "Review memory usage; increase Solr/Java heap or reduce workload.",
        "PROCESS_DISAPPEARED": "Confirm process termination; inspect system and logs.",
        "HIGH_RESOURCE_USAGE": "Identify top consumers; consider throttling or restarting.",
        "SOLR_CRASH": "Check Solr health, logs, and heap configuration.",
        "LOG_ERROR": "Investigate the referenced log error message.",
        "CORRELATED_INCIDENT": "Treat as a single incident chain and prioritize earliest root cause.",
    }
    default_hint = "Check logs and system status for further details."
    return hints.get(name, default_hint)


def get_system_metrics(case_dir: Path | None = None) -> dict[str, Any]:
    """Snapshot current system resource usage.

    Prefers the ``case_dir`` mount for disk stats when available; falls back
    to the system root partition otherwise.
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk_path = (
            str(case_dir) if case_dir is not None and case_dir.exists()
            else ("/" if not psutil.WINDOWS else "C:\\")
        )
        disk = psutil.disk_usage(disk_path)
        cpu_count = psutil.cpu_count(logical=True) or 1
        return {
            "cpu_percent": cpu_percent,
            "cpu_count": cpu_count,
            "cpu_cores_used": (cpu_percent / 100.0) * cpu_count,
            "memory_percent": memory.percent,
            "memory_used_gb": memory.used / (1024 ** 3),
            "memory_total_gb": memory.total / (1024 ** 3),
            "disk_free_gb": disk.free / (1024 ** 3),
            "disk_total_gb": disk.total / (1024 ** 3),
            "disk_percent": disk.percent,
        }
    except Exception:
        return {}

