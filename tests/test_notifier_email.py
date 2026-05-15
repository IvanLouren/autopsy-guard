from __future__ import annotations

import smtplib
from datetime import datetime
from unittest.mock import patch

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.notifiers.email import EmailNotifier
from autopsyguard.notifiers.email.report_builder import build_report_email


def make_config(tmp_path) -> MonitorConfig:
    cfg = MonitorConfig(case_dir=tmp_path)
    cfg.smtp_host = "smtp.example"
    cfg.smtp_port = 25
    cfg.smtp_user = "user"
    cfg.smtp_password = "pass"
    cfg.email_recipient = "recipient@example.com"
    cfg.email_sender = "sender@example.com"
    return cfg


def test_send_alert_builds_html_and_calls_dispatch(tmp_path):
    cfg = make_config(tmp_path)
    notifier = EmailNotifier(cfg)

    ev = CrashEvent(
        crash_type=CrashType.HANG,
        severity=Severity.WARNING,
        message="Solr slow response",
        timestamp=datetime.now(),
        details={"duration_seconds": 5, "pid": 123},
    )

    captured = {}

    def fake_dispatch(subject, html_body, *_, **kwargs):
        captured['subject'] = subject
        captured['html'] = html_body
        captured['plain'] = kwargs.get('plain_text')
        return True

    with patch.object(EmailNotifier, "_dispatch_email", side_effect=fake_dispatch):
        ok = notifier.send_alert([ev])
    assert ok is True
    assert "Solr slow response" in captured['html']
    assert "Aviso" in captured['subject'] or "CRÍTICO" not in captured['subject']


def test_dispatch_email_retries_and_succeeds(tmp_path):
    cfg = make_config(tmp_path)
    notifier = EmailNotifier(cfg)

    # Minimal inputs for dispatch
    subject = "subj"
    html = "<b>hi</b>"
    plain = "hi"

    # Simulate SMTP failures then success
    calls = {'count': 0}

    class DummySMTP:
        def __init__(self, *a, **k):
            pass
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def ehlo(self):
            return None
        def has_extn(self, name):
            return False
        def starttls(self):
            return None
        def login(self, user, pwd):
            return None
        def send_message(self, msg):
            calls['count'] += 1
            if calls['count'] < 3:
                raise smtplib.SMTPException("transient")
            return None

    with patch("autopsyguard.notifiers.email.notifier.smtplib.SMTP", DummySMTP):
        with patch("time.sleep", lambda s: None):
            ok = notifier._dispatch_email(subject, html, plain_text=plain)

    assert ok is True
    assert calls['count'] == 3



def test_send_report_includes_case_label_in_subject(tmp_path):
    cfg = make_config(tmp_path)
    cfg.email_case_label = "Caso Alfa"
    notifier = EmailNotifier(cfg)

    captured = {}

    def fake_dispatch(subject, html_body, *_, **kwargs):
        captured["subject"] = subject
        captured["html"] = html_body
        captured["plain"] = kwargs.get("plain_text")
        return True

    with patch.object(EmailNotifier, "_dispatch_email", side_effect=fake_dispatch):
        ok = notifier.send_report(
            "O sistema AutopsyGuard está ATIVO e a processar dados normalmente.",
            events_last_period=0,
            metrics_samples=[{"ts": 1.0, "cpu_percent": 10.0, "memory_percent": 20.0, "memory_used_bytes": 1, "memory_total_bytes": 2, "disk_free_bytes": 3, "disk_total_bytes": 4}],
        )

    assert ok is True
    assert "Caso Alfa" in captured["subject"]


def test_report_builder_includes_case_artifacts(tmp_path):
    case_dir = tmp_path / "Caso"
    case_dir.mkdir()
    (case_dir / "Caso.aut").write_text("<autopsy/>", encoding="utf-8")
    (case_dir / "autopsy.db").write_bytes(b"123456")
    log_dir = case_dir / "Log"
    log_dir.mkdir()
    (log_dir / "autopsy.log.0").write_text("line 1\nline 2\n", encoding="utf-8")
    module_dir = case_dir / "PhotoRec Carver"
    module_dir.mkdir()
    (module_dir / "artifact.txt").write_text("payload", encoding="utf-8")

    cfg = MonitorConfig(case_dir=case_dir)
    cfg.email_case_label = "Caso Alfa"
    cfg.language = "pt"

    subject, html_body, plain_text, _, _ = build_report_email(
        config=cfg,
        system_status="OK",
        events_last_period=0,
        uptime="1m 0s",
        recent_events=[],
        metrics_samples=[{"ts": 1.0, "cpu_percent": 10.0, "memory_percent": 20.0, "memory_used_bytes": 1, "memory_total_bytes": 2, "disk_free_bytes": 3, "disk_total_bytes": 4}],
        autopsy_pid=None,
    )

    assert "Caso Alfa" in subject
    assert "autopsy.db" in html_body
    assert "autopsy.log.0" in html_body
    assert "PhotoRec Carver" in html_body
    assert "Pastas de módulos" in plain_text
