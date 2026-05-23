"""SMTP email notifier for AutopsyGuard.

Handles immediate alert emails and delegates periodic report composition to
``report_builder``.  All HTML templates and formatting helpers live in
``templates``.
"""

from __future__ import annotations

import gzip
import logging
import smtplib
import threading
import time
from datetime import datetime, timedelta
from typing import Any

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, Severity
from autopsyguard.notifiers.base import BaseNotifier
from autopsyguard.notifiers.email.templates import (
    BASE_TEMPLATE,
    ALERT_EVENT_ROW,
    METRIC_BOX,
    RESOURCE_THRESHOLDS,
    get_case_label,
    get_event_icon,
    get_severity_color,
    format_details,
    short_event_id,
    suggestion_for_event,
    get_system_metrics,
)
from autopsyguard.notifiers.email.report_builder import build_report_email
from autopsyguard.utils.process_utils import find_autopsy_pid as _get_autopsy_pid
from autopsyguard.utils.messages import tr

logger = logging.getLogger(__name__)


class EmailNotifier(BaseNotifier):
    """Sends HTML email alerts and reports using Python's built-in smtplib."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__()
        self.config = config
        self._enabled = bool(config.smtp_host and config.email_recipient)
        # When True, email dispatch runs in a daemon thread so it never blocks
        # the monitor polling loop. Defaults to False for test compatibility.
        self._async_send = bool(getattr(config, "smtp_async", False))
        self._event_history: list[tuple[datetime, CrashEvent]] = []
        self._max_history = 50
        self._history_lock = threading.Lock()

    # ------------------------------------------------------------------
    # BaseNotifier implementation
    # ------------------------------------------------------------------

    def is_enabled(self) -> bool:
        return self._enabled

    def send_alert(self, events: list[CrashEvent]) -> bool:
        """Send an immediate alert email for critical/warning events."""
        if not self._enabled or not events:
            return False

        for event in events:
            self._record_event(event)

        critical_count = sum(1 for e in events if e.severity == Severity.CRITICAL)
        warning_count = sum(1 for e in events if e.severity == Severity.WARNING)

        case_label = get_case_label(self.config)
        subject = (
            f"🚨 [AutopsyGuard] {tr(self.config, 'alert_critical_subject', count=critical_count)} - {case_label}"
            if critical_count > 0
            else f"⚠️ [AutopsyGuard] {tr(self.config, 'alert_warning_subject', count=warning_count)} - {case_label}"
        )

        event_rows = "".join(
            ALERT_EVENT_ROW.format(
                icon=get_event_icon(e.crash_type.name)[0],
                icon_bg=get_event_icon(e.crash_type.name)[1],
                severity=e.severity.name,
                severity_color=get_severity_color(e.severity),
                crash_type=e.crash_type.name.replace("_", " "),
                message=e.message,
                details_html=format_details(e.details),
            )
            for e in events
        )

        metrics = get_system_metrics(self.config.case_dir)
        autopsy_pid = _get_autopsy_pid()
        metrics_html = self._build_alert_metrics_bar(metrics, autopsy_pid)

        summary = f"""
        <div style="margin-bottom:24px;">
            <p style="color:#4b5563; font-size:15px; line-height:1.6; margin:0 0 16px 0;">
                {tr(self.config, 'alert_summary', count=len(events))}
            </p>
            <table role="presentation" cellspacing="0" cellpadding="0" style="margin-bottom:8px;">
                <tr>
                    <td style="background-color:#dc2626; color:white; padding:4px 12px; border-radius:4px; font-size:13px; font-weight:600;">{tr(self.config, 'critical_count', count=critical_count)}</td>
                    <td width="8"></td>
                    <td style="background-color:#d97706; color:white; padding:4px 12px; border-radius:4px; font-size:13px; font-weight:600;">{tr(self.config, 'warning_count', count=warning_count)}</td>
                </tr>
            </table>
        </div>
        """

        body_content = metrics_html + summary + f"""
        <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr><td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                    <strong style="color:#374151; font-size:14px;">📋 {tr(self.config, 'detected_events')}</strong>
                </td></tr>
                {event_rows}
            </table>
        </div>

        <div style="margin-top:24px; padding:16px; background-color:#fef3c7; border-radius:8px; border-left:4px solid #d97706;">
            <p style="color:#92400e; font-size:13px; margin:0;">
                <strong>💡 {tr(self.config, 'recommendation')}:</strong> {tr(self.config, 'recommendation_text')}
            </p>
        </div>

        <div style="margin-top:12px; padding:12px 16px; background-color:#f3f4f6; border-radius:8px;">
            <p style="color:#6b7280; font-size:12px; margin:0;">
                📁 <strong>{tr(self.config, 'logs')}:</strong> {case_label}
            </p>
        </div>
        """

        html_body = BASE_TEMPLATE.format(
            header_color_start="#dc2626" if critical_count > 0 else "#d97706",
            header_color_end="#991b1b" if critical_count > 0 else "#b45309",
            header_icon="🚨" if critical_count > 0 else "⚠️",
            header_title=tr(self.config, "alert_header_title"),
            header_subtitle=tr(self.config, "alert_header_subtitle"),
            timestamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            case_name=f"📁 {case_label}",
            body_content=body_content,
            footer_system=tr(self.config, "footer_system"),
            auto_email_note=tr(self.config, "auto_email"),
        )

        plain_lines = [
            subject,
            "",
            f"{tr(self.config, 'plain_critical_count')}: {critical_count}",
            f"{tr(self.config, 'plain_warning_count')}: {warning_count}",
            f"{tr(self.config, 'plain_uptime')}: {self.get_uptime()}",
            "",
        ]
        for ev in events[:10]:
            plain_lines.append(f"[{short_event_id(ev)}] {ev.severity.name}: {ev.message}")
            plain_lines.append(f"    {tr(self.config, 'plain_hint')}: {suggestion_for_event(ev, self.config)}")
        plain_lines += ["", tr(self.config, "metric_note_multicore")]
        plain_text = "\n".join(plain_lines)

        # Collect unique log files referenced in events and gzip them as attachments
        attachments: list[tuple[str, bytes, str]] = []
        seen_files: set[str] = set()
        for ev in events:
            fpath = (ev.details or {}).get("file")
            if fpath and fpath not in seen_files:
                seen_files.add(fpath)
                try:
                    import os
                    from pathlib import Path as _P
                    max_bytes = 2 * 1024 * 1024  # 2MB maximum per attachment
                    
                    with open(fpath, "rb") as f:
                        f.seek(0, os.SEEK_END)
                        file_size = f.tell()
                        start_pos = max(0, file_size - max_bytes)
                        f.seek(start_pos, os.SEEK_SET)
                        raw = f.read(max_bytes)
                        
                        if start_pos > 0:
                            raw = b"[TRUNCATED BY AUTOPSYGUARD - PREVIOUS LOG ENTRIES OMITTED DUE TO SIZE]\n\n" + raw

                    compressed = gzip.compress(raw)
                    fname = _P(fpath).name + ".gz"
                    attachments.append((fname, compressed, "application/gzip"))
                except Exception:
                    pass

        return self._dispatch_email(subject, html_body, plain_text=plain_text,
                                    attachments=attachments if attachments else None)

    def send_report(
        self,
        system_status: str,
        events_last_period: int,
        metrics_samples: list[dict[str, Any]] | None = None,
        telemetry: dict[str, Any] | None = None,
    ) -> bool:
        """Send a periodic heartbeat report."""
        if not self._enabled:
            return False

        recent_events = self._get_recent_events(self.config.report_interval_hours)
        autopsy_pid = _get_autopsy_pid()

        subject, html_body, plain_text, inline_images, attachments = build_report_email(
            config=self.config,
            system_status=system_status,
            events_last_period=events_last_period,
            uptime=self.get_uptime(),
            recent_events=recent_events,
            metrics_samples=metrics_samples,
            autopsy_pid=autopsy_pid,
            telemetry=telemetry,
        )

        return self._dispatch_email(
            subject, html_body,
            inline_images=inline_images,
            attachments=attachments,
            plain_text=plain_text,
        )

    def send_ingest_report(self, duration_seconds: float) -> bool:
        """Send a notification that an Autopsy ingest job has completed."""
        if not self._enabled:
            return False

        hours, rem = divmod(int(duration_seconds), 3600)
        minutes, seconds = divmod(rem, 60)
        duration_str = f"{hours}h {minutes}m {seconds}s"

        subject = f"🏁 [AutopsyGuard] {tr(self.config, 'ingest_done_subject')} - {get_case_label(self.config)}"
        body_content = f"""
        <div style="margin-bottom:24px; text-align:center;">
            <div style="font-size:48px; margin-bottom:16px;">🏁</div>
            <h2 style="color:#111827; margin:0 0 8px 0;">{tr(self.config, 'ingest_done_title')}</h2>
            <p style="color:#4b5563; font-size:16px; margin:0;">{tr(self.config, 'ingest_done_text')}</p>
        </div>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:20px;">
            <tr><td style="background-color:#f8f9fa; border-radius:8px; padding:20px;">
                <div style="font-size:12px; color:#6b7280; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px;">⏱️ {tr(self.config, 'processing_time')}</div>
                <div style="font-size:28px; font-weight:bold; color:#2563eb;">{duration_str}</div>
            </td></tr>
        </table>
        """

        case_label = get_case_label(self.config)
        html_body = BASE_TEMPLATE.format(
            header_color_start="#2563eb",
            header_color_end="#1d4ed8",
            header_icon="✅",
            header_title=tr(self.config, "ingest_done_header_title"),
            header_subtitle=tr(self.config, "ingest_done_header_subtitle"),
            timestamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            case_name=f"📁 {case_label}",
            body_content=body_content,
            footer_system=tr(self.config, "footer_system"),
            auto_email_note=tr(self.config, "auto_email"),
        )
        plain_text = f"{tr(self.config, 'ingest_done_title')}.\n{tr(self.config, 'processing_time')}: {duration_str}"
        return self._dispatch_email(subject, html_body, plain_text=plain_text)

    def send_startup_message(self) -> bool:
        """Send a brief notification that the monitor has started."""
        if not self._enabled:
            return False

        case_label = get_case_label(self.config)
        subject = f"✅ [AutopsyGuard] {tr(self.config, 'startup_subject')} - {case_label}"
        
        metrics = get_system_metrics(self.config.case_dir)
        autopsy_pid = _get_autopsy_pid()
        metrics_html = self._build_alert_metrics_bar(metrics, autopsy_pid)
        
        def _conf_row(icon: str, label: str, value: str) -> str:
            return f"""
            <tr>
                <td style="padding:8px 16px; border-bottom:1px solid #f3f4f6;">
                    <span style="font-size:14px;">{icon}</span>
                    <span style="color:#6b7280; font-size:12px; margin-left:8px;">{label}</span>
                </td>
                <td align="right" style="padding:8px 16px; border-bottom:1px solid #f3f4f6;">
                    <span style="color:#111827; font-size:12px; font-weight:600;">{value}</span>
                </td>
            </tr>"""

        channels = ["Email"]
        if getattr(self.config, "whatsapp_phone", None) or getattr(self.config, "whatsapp_apikey", None):
            channels.append("WhatsApp")
        if getattr(self.config, "telegram_chat_id", None) or getattr(self.config, "telegram_bot_token", None):
            channels.append("Telegram")

        config_rows = (
            _conf_row("⏱️", tr(self.config, "poll_interval"), f"{self.config.poll_interval}s")
            + _conf_row("⏳", tr(self.config, "hang_timeout"), f"{self.config.hang_timeout}s")
            + _conf_row("📊", "Report Interval", f"{self.config.report_interval_hours}h")
            + _conf_row("📡", "Active Channels", ", ".join(channels))
        )
        
        body_content = f"""
        <div style="margin-bottom:24px; text-align:center;">
            <div style="font-size:48px; margin-bottom:16px;">🚀</div>
            <h2 style="color:#111827; margin:0 0 8px 0;">{tr(self.config, 'startup_title')}</h2>
            <p style="color:#4b5563; font-size:16px; margin:0;">{tr(self.config, 'startup_text')}</p>
        </div>
        {metrics_html}
        <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr><td colspan="2" style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                    <strong style="color:#374151; font-size:13px; text-transform:uppercase; letter-spacing:1px;">⚙️ Monitoring Configuration</strong>
                </td></tr>
                {config_rows}
            </table>
        </div>
        """
        html_body = BASE_TEMPLATE.format(
            header_color_start="#10b981",
            header_color_end="#059669",
            header_icon="✅",
            header_title=tr(self.config, "startup_header_title"),
            header_subtitle=tr(self.config, "startup_header_subtitle"),
            timestamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            case_name=f"📁 {case_label}",
            body_content=body_content,
            footer_system=tr(self.config, "footer_system"),
            auto_email_note=tr(self.config, "auto_email"),
        )
        plain_text = f"✅ {tr(self.config, 'startup_subject')}\n{tr(self.config, 'startup_text')}\nAutopsy PID: {autopsy_pid or 'N/A'} | CPU: {metrics.get('cpu_percent', 0.0):.1f}% | RAM: {metrics.get('memory_percent', 0.0):.1f}%\nPolling: {self.config.poll_interval}s | Hang: {self.config.hang_timeout}s | Reports: {self.config.report_interval_hours}h | Channels: {', '.join(channels)}"
        return self._dispatch_email(subject, html_body, plain_text=plain_text)

    def send_shutdown_message(self, stats: dict[str, Any]) -> bool:
        """Send a session summary when Autopsy shuts down gracefully."""
        if not self._enabled:
            return False

        case_label = get_case_label(self.config)
        subject = f"🏁 [AutopsyGuard] {tr(self.config, 'shutdown_subject')} - {case_label}"

        def _stat_row(icon: str, label: str, value: str) -> str:
            return f"""
            <tr>
                <td style="padding:10px 16px; border-bottom:1px solid #f3f4f6;">
                    <span style="font-size:14px;">{icon}</span>
                    <span style="color:#6b7280; font-size:13px; margin-left:8px;">{label}</span>
                </td>
                <td align="right" style="padding:10px 16px; border-bottom:1px solid #f3f4f6;">
                    <span style="color:#111827; font-size:13px; font-weight:600;">{value}</span>
                </td>
            </tr>"""

        total = stats.get("total_events", 0)
        critical = stats.get("critical_count", 0)
        warnings = stats.get("warning_count", 0)
        reports = stats.get("reports_sent", 0)
        uptime = stats.get("uptime", "N/A")
        case_size = stats.get("case_size", "N/A")
        db_size = stats.get("db_size", "N/A")

        rows = (
            _stat_row("⏱️", tr(self.config, "shutdown_session_duration"), uptime)
            + _stat_row("📊", tr(self.config, "shutdown_total_events"), str(total))
            + _stat_row("🔴", tr(self.config, "shutdown_critical"), str(critical))
            + _stat_row("🟡", tr(self.config, "shutdown_warnings"), str(warnings))
            + _stat_row("📧", tr(self.config, "shutdown_reports_sent"), str(reports))
            + _stat_row("🗄️", tr(self.config, "shutdown_case_size"), case_size)
            + _stat_row("🗃️", tr(self.config, "shutdown_db_size"), db_size)
        )

        body_content = f"""
        <div style="margin-bottom:24px; text-align:center;">
            <div style="font-size:48px; margin-bottom:16px;">🏁</div>
            <h2 style="color:#111827; margin:0 0 8px 0;">{tr(self.config, 'shutdown_title')}</h2>
            <p style="color:#4b5563; font-size:16px; margin:0;">{tr(self.config, 'shutdown_text')}</p>
        </div>
        <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden; margin-bottom:20px;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                {rows}
            </table>
        </div>
        """

        html_body = BASE_TEMPLATE.format(
            header_color_start="#6366f1",
            header_color_end="#4338ca",
            header_icon="🏁",
            header_title=tr(self.config, "shutdown_header_title"),
            header_subtitle=tr(self.config, "shutdown_header_subtitle"),
            timestamp=datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            case_name=f"📁 {case_label}",
            body_content=body_content,
            footer_system=tr(self.config, "footer_system"),
            auto_email_note=tr(self.config, "auto_email"),
        )

        plain_lines = [
            f"🏁 {tr(self.config, 'shutdown_subject')} - {case_label}",
            tr(self.config, "shutdown_text"),
            "",
            f"{tr(self.config, 'shutdown_session_duration')}: {uptime}",
            f"{tr(self.config, 'shutdown_total_events')}: {total}",
            f"{tr(self.config, 'shutdown_critical')}: {critical}",
            f"{tr(self.config, 'shutdown_warnings')}: {warnings}",
            f"{tr(self.config, 'shutdown_reports_sent')}: {reports}",
            f"{tr(self.config, 'shutdown_case_size')}: {case_size}",
            f"{tr(self.config, 'shutdown_db_size')}: {db_size}",
        ]
        return self._dispatch_email(subject, html_body, plain_text="\n".join(plain_lines))

    # ------------------------------------------------------------------
    # Event history (used by report builder for recent-events section)
    # ------------------------------------------------------------------

    def _record_event(self, event: CrashEvent) -> None:
        with self._history_lock:
            self._event_history.append((datetime.now(), event))
            if len(self._event_history) > self._max_history:
                self._event_history = self._event_history[-self._max_history:]

    def _subject_with_case(self, subject: str) -> str:
        case_label = get_case_label(self.config)
        return f"{subject} - {case_label}"

    def _get_recent_events(self, hours: float = 1.0) -> list[tuple[datetime, CrashEvent]]:
        cutoff = datetime.now() - timedelta(hours=hours)
        with self._history_lock:
            return [(ts, ev) for ts, ev in self._event_history if ts >= cutoff]

    # Keep the old public names as aliases so any external callers still work
    def record_event(self, event: CrashEvent) -> None:  # pragma: no cover
        self._record_event(event)

    def get_recent_events(self, hours: float = 1.0) -> list[tuple[datetime, CrashEvent]]:  # pragma: no cover
        return self._get_recent_events(hours)

    # ------------------------------------------------------------------
    # Alert metrics bar (inline, not shared with reports)
    # ------------------------------------------------------------------

    def _build_alert_metrics_bar(self, metrics: dict[str, Any], autopsy_pid: int | None) -> str:
        if not metrics:
            return ""
        cpu_color = "#dc2626" if metrics.get("cpu_percent", 0) > RESOURCE_THRESHOLDS["cpu_warn"] else "#10b981"
        mem_color = "#dc2626" if metrics.get("memory_percent", 0) > RESOURCE_THRESHOLDS["mem_warn"] else "#10b981"
        disk_color = "#dc2626" if metrics.get("disk_free_gb", 100) < RESOURCE_THRESHOLDS["disk_warn_gb"] else "#10b981"
        cpu_pct = metrics.get("cpu_percent", 0)
        cpu_count = metrics.get("cpu_count")
        if cpu_count:
            cores_used = metrics.get("cpu_cores_used", 0.0)
            cpu_display = f"{cpu_pct:.1f}% • {cores_used:.1f}/{cpu_count} cores"
        else:
            cpu_display = f"{cpu_pct:.1f}%"
        return f"""
        <div style="margin-bottom:20px; padding:16px; background-color:#f8f9fa; border-radius:8px;">
            <div style="font-size:12px; color:#6b7280; margin-bottom:12px; text-transform:uppercase; letter-spacing:1px;">📊 {tr(self.config, 'system_status')}</div>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr>
                {METRIC_BOX.format(icon="🖥️", value=cpu_display, label=tr(self.config, 'cpu'), color=cpu_color)}
                {METRIC_BOX.format(icon="🧠", value=f"{metrics.get('memory_percent', 0):.1f}%", label=tr(self.config, 'memory'), color=mem_color)}
                {METRIC_BOX.format(icon="🗄️", value=f"{metrics.get('disk_free_gb', 0):.1f}GB", label=tr(self.config, 'disk_free'), color=disk_color)}
                {METRIC_BOX.format(icon="🔍", value=str(autopsy_pid or 'N/A'), label=tr(self.config, 'autopsy_pid_label'), color="#3b82f6")}
            </tr></table>
            <div style="font-size:11px; color:#6b7280; margin-top:8px;">{tr(self.config, 'metric_note_multicore')}</div>
        </div>
        """

    # ------------------------------------------------------------------
    # SMTP dispatch (unchanged logic)
    # ------------------------------------------------------------------

    def _dispatch_email(
        self,
        subject: str,
        html_body: str,
        *,
        inline_images: list[tuple[str, bytes, str]] | None = None,
        attachments: list[tuple[str, bytes, str]] | None = None,
        plain_text: str | None = None,
    ) -> bool:
        """Construct the MIME message and talk to the SMTP server."""
        from email.message import EmailMessage

        msg = EmailMessage()
        msg.set_content(plain_text or tr(self.config, "html_fallback"))
        msg.add_alternative(html_body, subtype="html")

        if inline_images:
            html_part = None
            try:
                html_part = msg.get_body(preferencelist=("html",))
            except Exception:
                pass
            if html_part is None:
                for part in msg.iter_parts():
                    if part.get_content_type() == "text/html":
                        html_part = part
                        break
            if html_part is not None:
                for cid, data, subtype in inline_images:
                    try:
                        html_part.add_related(data, maintype="image", subtype=subtype, cid=f"<{cid}>")
                    except Exception:
                        logger.debug("Could not add related image %s", cid)

        if attachments:
            for filename, data, mime in attachments:
                try:
                    maintype, subtype = mime.split("/", 1)
                except Exception:
                    maintype, subtype = "application", "octet-stream"
                msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)

        msg["Subject"] = subject
        msg["From"] = self.config.email_sender
        msg["To"] = self.config.email_recipient

        def _send_sync() -> bool:
            max_attempts, base_backoff = 3, 1.0
            last_exc: Exception | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    logger.debug("Connecting to SMTP %s:%d (attempt %d)", self.config.smtp_host, self.config.smtp_port, attempt)
                    smtp_cls = smtplib.SMTP_SSL if getattr(self.config, "smtp_use_ssl", False) else smtplib.SMTP
                    with smtp_cls(self.config.smtp_host, self.config.smtp_port, timeout=30) as server:
                        try:
                            server.ehlo()
                            if not getattr(self.config, "smtp_use_ssl", False) and server.has_extn("STARTTLS"):
                                server.starttls()
                                server.ehlo()
                        except Exception:
                            logger.debug("SMTP server did not respond to EHLO/STARTTLS probe; continuing")
                        if self.config.smtp_password:
                            server.login(self.config.smtp_user, self.config.smtp_password)
                        server.send_message(msg)
                    logger.info("📧 Email sent: %s", subject[:60])
                    return True
                except (smtplib.SMTPException, OSError, TimeoutError) as e:
                    last_exc = e
                    logger.warning("Failed to send email (attempt %d/%d): %s", attempt, max_attempts, e)
                    if attempt < max_attempts:
                        time.sleep(base_backoff * (2 ** (attempt - 1)))
            logger.error("❌ Failed to send email after %d attempts: %s", max_attempts, last_exc)
            return False

        if self._async_send:
            def _thread_target() -> None:
                start = time.time()
                ok = _send_sync()
                duration = time.time() - start
                try:
                    poll = float(self.config.poll_interval)
                except Exception:
                    poll = 0.0
                if poll > 0 and duration > 0.1 * poll:
                    logger.warning("Email dispatch took %.2fs (>10%% of poll_interval %.1fs)", duration, poll)
                if not ok:
                    logger.debug("Async email dispatch failed (see earlier logs)")

            t = threading.Thread(target=_thread_target, daemon=True)
            t.start()
            return True

        return _send_sync()


