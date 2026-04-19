from __future__ import annotations

import smtplib
from datetime import datetime
from unittest.mock import patch

import pytest

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.notifier import EmailNotifier


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

    with patch("autopsyguard.notifier.smtplib.SMTP", DummySMTP):
        with patch("time.sleep", lambda s: None):
            ok = notifier._dispatch_email(subject, html, plain_text=plain)

    assert ok is True
    assert calls['count'] == 3
