"""SMTP email notifier for AutopsyGuard.

Handles immediate alert emails and delegates periodic report composition to
``report_builder``.  All HTML templates and formatting helpers live in
``templates``.
"""

from __future__ import annotations

import logging
import smtplib
import threading
import time
from pathlib import Path
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
from autopsyguard.notifiers.email.oauth import (
    SMTPOAuthError,
    load_token_file,
    refresh_access_token,
    save_token_file,
    token_is_fresh,
    xoauth2_initial_response,
)
from autopsyguard.utils.process_utils import find_autopsy_pid as _get_autopsy_pid

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

        subject = (
            f"🚨 [AutopsyGuard] CRÍTICO: {critical_count} problema(s) detetado(s)"
            if critical_count > 0
            else f"⚠️ [AutopsyGuard] Aviso: {warning_count} anomalia(s) detetada(s)"
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
        case_label = get_case_label(self.config)

        metrics_html = self._build_alert_metrics_bar(metrics, autopsy_pid)

        summary = f"""
        <div style="margin-bottom:24px;">
            <p style="color:#4b5563; font-size:15px; line-height:1.6; margin:0 0 16px 0;">
                O sistema de monitorização detetou <strong>{len(events)} evento(s)</strong> que requerem a sua atenção.
            </p>
            <table role="presentation" cellspacing="0" cellpadding="0" style="margin-bottom:8px;">
                <tr>
                    <td style="background-color:#dc2626; color:white; padding:4px 12px; border-radius:4px; font-size:13px; font-weight:600;">{critical_count} Crítico(s)</td>
                    <td width="8"></td>
                    <td style="background-color:#d97706; color:white; padding:4px 12px; border-radius:4px; font-size:13px; font-weight:600;">{warning_count} Aviso(s)</td>
                </tr>
            </table>
        </div>
        """

        body_content = metrics_html + summary + f"""
        <div style="border:1px solid #e5e7eb; border-radius:8px; overflow:hidden;">
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr><td style="background-color:#f9fafb; padding:12px 16px; border-bottom:1px solid #e5e7eb;">
                    <strong style="color:#374151; font-size:14px;">📋 Eventos Detetados</strong>
                </td></tr>
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
                📁 <strong>Logs:</strong> {case_label}
            </p>
        </div>
        """

        html_body = BASE_TEMPLATE.format(
            header_color_start="#dc2626" if critical_count > 0 else "#d97706",
            header_color_end="#991b1b" if critical_count > 0 else "#b45309",
            header_icon="🚨" if critical_count > 0 else "⚠️",
            header_title="Alerta de Sistema",
            header_subtitle="Foram detetadas anomalias que requerem atenção",
            timestamp=datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
            case_name=f"📁 {case_label}",
            body_content=body_content,
        )

        plain_lines = [subject, "", f"Crítico(s): {critical_count}", f"Aviso(s): {warning_count}", f"Uptime: {self.get_uptime()}", ""]
        for ev in events[:10]:
            plain_lines.append(f"[{short_event_id(ev)}] {ev.severity.name}: {ev.message}")
            plain_lines.append(f"    Sugestão: {suggestion_for_event(ev)}")
        plain_lines += ["", "Nota: 'Process %' pode exceder 100% — conta núcleos usados."]
        plain_text = "\n".join(plain_lines)

        return self._dispatch_email(subject, html_body, plain_text=plain_text)

    def send_report(
        self,
        system_status: str,
        events_last_period: int,
        metrics_samples: list[dict[str, Any]] | None = None,
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

        subject = "🏁 [AutopsyGuard] Ingestão Concluída"
        body_content = f"""
        <div style="margin-bottom:24px; text-align:center;">
            <div style="font-size:48px; margin-bottom:16px;">🏁</div>
            <h2 style="color:#111827; margin:0 0 8px 0;">Ingestão Concluída</h2>
            <p style="color:#4b5563; font-size:16px; margin:0;">O processo de ingestão no Autopsy terminou com sucesso.</p>
        </div>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-bottom:20px;">
            <tr><td style="background-color:#f8f9fa; border-radius:8px; padding:20px;">
                <div style="font-size:12px; color:#6b7280; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px;">⏱️ Tempo de Processamento</div>
                <div style="font-size:28px; font-weight:bold; color:#2563eb;">{duration_str}</div>
            </td></tr>
        </table>
        """

        case_label = get_case_label(self.config)
        html_body = BASE_TEMPLATE.format(
            header_color_start="#2563eb",
            header_color_end="#1d4ed8",
            header_icon="✅",
            header_title="Ingestão Terminada",
            header_subtitle="Resumo do processamento",
            timestamp=datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
            case_name=f"📁 {case_label}",
            body_content=body_content,
        )
        plain_text = f"Ingestão Concluída.\nTempo total de processamento: {duration_str}"
        return self._dispatch_email(subject, html_body, plain_text=plain_text)

    # ------------------------------------------------------------------
    # Event history (used by report builder for recent-events section)
    # ------------------------------------------------------------------

    def _record_event(self, event: CrashEvent) -> None:
        with self._history_lock:
            self._event_history.append((datetime.now(), event))
            if len(self._event_history) > self._max_history:
                self._event_history = self._event_history[-self._max_history:]

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
            cpu_display = f"{cpu_pct:.1f}% • {cores_used:.1f}/{cpu_count} núcleos"
        else:
            cpu_display = f"{cpu_pct:.1f}%"
        return f"""
        <div style="margin-bottom:20px; padding:16px; background-color:#f8f9fa; border-radius:8px;">
            <div style="font-size:12px; color:#6b7280; margin-bottom:12px; text-transform:uppercase; letter-spacing:1px;">📊 Estado do Sistema no Momento do Alerta</div>
            <table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr>
                {METRIC_BOX.format(icon="💻", value=cpu_display, label="CPU", color=cpu_color)}
                {METRIC_BOX.format(icon="🧠", value=f"{metrics.get('memory_percent', 0):.1f}%", label="Memória", color=mem_color)}
                {METRIC_BOX.format(icon="💾", value=f"{metrics.get('disk_free_gb', 0):.1f}GB", label="Disco Livre", color=disk_color)}
                {METRIC_BOX.format(icon="🔍", value=str(autopsy_pid or 'N/A'), label="Autopsy PID", color="#3b82f6")}
            </tr></table>
            <div style="font-size:11px; color:#6b7280; margin-top:8px;">Nota: 'Process %' pode exceder 100% — conta núcleos usados.</div>
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
        msg.set_content(plain_text or "O seu cliente de e-mail não suporta HTML. Por favor use um cliente moderno.")
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
                        auth_mode = (getattr(self.config, "smtp_auth_mode", "password") or "password").strip().lower()
                        if auth_mode == "oauth":
                            self._smtp_auth_oauth(server)
                        elif self.config.smtp_password:
                            server.login(self.config.smtp_user, self.config.smtp_password)
                        server.send_message(msg)
                    logger.info("📧 Email enviado: %s", subject[:60])
                    return True
                except (smtplib.SMTPException, OSError, TimeoutError) as e:
                    last_exc = e
                    logger.warning("Falha ao enviar email (attempt %d/%d): %s", attempt, max_attempts, e)
                    if attempt < max_attempts:
                        time.sleep(base_backoff * (2 ** (attempt - 1)))
            logger.error("❌ Falha ao enviar email após %d tentativas: %s", max_attempts, last_exc)
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

    def _smtp_auth_oauth(self, server: smtplib.SMTP) -> None:
        """Authenticate against SMTP using OAuth2 (XOAUTH2)."""
        user = (self.config.smtp_user or "").strip()
        if not user:
            raise SMTPOAuthError("smtp_user is required for OAuth SMTP authentication")

        access_token = self._get_oauth_access_token()
        xoauth2 = xoauth2_initial_response(user, access_token)
        code, response = server.docmd("AUTH", "XOAUTH2 " + xoauth2)
        if code != 235:
            raise smtplib.SMTPAuthenticationError(code, response)

    def _get_oauth_access_token(self) -> str:
        token_path = self._resolve_oauth_token_path()
        token_data = load_token_file(token_path)

        provider = (
            (self.config.smtp_oauth_provider or "").strip().lower()
            or str(token_data.get("provider", "")).strip().lower()
        )
        client_id = (self.config.smtp_oauth_client_id or "").strip() or str(token_data.get("client_id", "")).strip()
        client_secret = (self.config.smtp_oauth_client_secret or "").strip() or str(
            token_data.get("client_secret", "")
        ).strip()
        tenant = (self.config.smtp_oauth_tenant or "").strip() or str(token_data.get("tenant", "common")).strip()
        refresh_token = str(token_data.get("refresh_token", "")).strip()

        if not provider:
            raise SMTPOAuthError("Missing OAuth provider (smtp_oauth_provider)")
        if not client_id:
            raise SMTPOAuthError("Missing OAuth client id (smtp_oauth_client_id)")
        if not refresh_token:
            raise SMTPOAuthError("OAuth token file does not contain refresh_token")

        if token_is_fresh(token_data):
            access_token = str(token_data.get("access_token", "")).strip()
            if access_token:
                return access_token

        refreshed = refresh_access_token(
            provider=provider,
            refresh_token=refresh_token,
            client_id=client_id,
            client_secret=client_secret,
            tenant=tenant,
            timeout=30.0,
        )
        now = time.time()
        expires_in = int(refreshed.get("expires_in", 3600))
        token_data.update(
            {
                "provider": provider,
                "client_id": client_id,
                "client_secret": client_secret,
                "tenant": tenant,
                "access_token": refreshed["access_token"],
                "refresh_token": refreshed.get("refresh_token", refresh_token),
                "token_type": refreshed.get("token_type", "Bearer"),
                "scope": refreshed.get("scope", token_data.get("scope", "")),
                "expires_at": now + max(expires_in, 60),
                "updated_at": now,
            }
        )
        save_token_file(token_path, token_data)
        return str(token_data["access_token"])

    def _resolve_oauth_token_path(self) -> Path:
        if self.config.smtp_oauth_token_file is None:
            raise SMTPOAuthError("smtp_oauth_token_file is required for smtp_auth_mode=oauth")
        return Path(self.config.smtp_oauth_token_file)
