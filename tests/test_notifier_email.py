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
    assert "Warning" in captured['subject'] or "CRITICAL" not in captured['subject']


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


def test_send_alert_includes_case_label_in_subject(tmp_path):
    cfg = make_config(tmp_path)
    cfg.email_case_label = "Caso Alfa"
    notifier = EmailNotifier(cfg)

    ev = CrashEvent(
        crash_type=CrashType.HANG,
        severity=Severity.WARNING,
        message="Solr slow response",
        timestamp=datetime.now(),
        details={},
    )

    captured = {}

    def fake_dispatch(subject, html_body, *_, **kwargs):
        captured["subject"] = subject
        return True

    with patch.object(EmailNotifier, "_dispatch_email", side_effect=fake_dispatch):
        ok = notifier.send_alert([ev])

    assert ok is True
    assert "Caso Alfa" in captured["subject"]


def test_send_startup_and_ingest_include_case_label_in_subject(tmp_path):
    cfg = make_config(tmp_path)
    cfg.email_case_label = "Caso Alfa"
    notifier = EmailNotifier(cfg)

    captured_subjects: list[str] = []

    def fake_dispatch(subject, html_body, *_, **kwargs):
        captured_subjects.append(subject)
        return True

    with patch.object(EmailNotifier, "_dispatch_email", side_effect=fake_dispatch):
        assert notifier.send_startup_message() is True
        assert notifier.send_ingest_report(65.0) is True

    assert any("Caso Alfa" in s for s in captured_subjects)
    assert len(captured_subjects) == 2


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
    assert "Module Folders" in plain_text


def test_report_builder_includes_solr_and_recent_module_summary(tmp_path):
    case_dir = tmp_path / "Caso"
    case_dir.mkdir()
    (case_dir / "Caso.aut").write_text("<autopsy/>", encoding="utf-8")

    cfg = MonitorConfig(case_dir=case_dir)
    cfg.email_case_label = "Case Alpha"

    telemetry = {
        "autopsy_db": {"exists": False, "size_bytes": None, "updated_at": None},
        "autopsy_log": {"exists": True, "size_bytes": 120, "updated_at": "2026-05-15 10:00:00", "line_count": 20},
        "case_size_bytes": 1024,
        "module_folders": [{"name": "PhotoRec Carver", "size_bytes": 100, "updated_at": "2026-05-15 11:22:00"}],
        "module_activity": [
            {"module": "Keyword Search", "state": "active", "line": "Keyword Search running", "timestamp": "2026-05-15 11:20:00"},
            {"module": "Solr", "state": "active", "line": "Solr ping ok", "timestamp": "2026-05-15 11:21:00"},
        ],
        "solr": {
            "state": "down",
            "response_time_seconds": 0.9,
            "checked_at": "2026-05-15 11:23:00",
            "error": "Connection refused",
            "heap_usage_percent": 40.0,
            "cpu_percent": 5.0,
        },
        "autopsy_cpu_timeline": {"current": 7.0, "minus_5m": 5.0, "minus_15m": 2.0},
    }

    _, html_body, plain_text, _, _ = build_report_email(
        config=cfg,
        system_status="OK",
        events_last_period=0,
        uptime="1m 0s",
        recent_events=[],
        metrics_samples=[{"ts": 1.0, "cpu_percent": 10.0, "memory_percent": 20.0, "memory_used_bytes": 1, "memory_total_bytes": 2, "disk_free_bytes": 3, "disk_total_bytes": 4}],
        autopsy_pid=None,
        telemetry=telemetry,
    )

    assert "Current/Recent Module" in html_body
    assert "Keyword/SOLR Activity" in html_body
    assert "checked at=" in html_body
    assert "last error=" in html_body
    assert "Possible transient/local access contention." in html_body
    assert "autopsy.db: missing" in plain_text


def test_report_builder_solr_up_http400_uses_warning_context_and_timestamp_fallback(tmp_path):
    case_dir = tmp_path / "Case"
    case_dir.mkdir()
    (case_dir / "Case.aut").write_text("<autopsy/>", encoding="utf-8")

    cfg = MonitorConfig(case_dir=case_dir)
    telemetry = {
        "autopsy_db": {"exists": False, "size_bytes": None, "updated_at": None},
        "autopsy_log": {"exists": True, "size_bytes": 120, "updated_at": "2026-05-15 18:31:42", "line_count": 20},
        "case_size_bytes": 1024,
        "module_folders": [{"name": "PhotoRec Carver", "size_bytes": 100, "updated_at": "2026-05-15 11:22:00"}],
        "module_activity": [
            {"module": "Ingest", "state": "start", "line": "Starting ingest job", "timestamp": None},
            {"module": "Solr", "state": "active", "line": "Solr ping ok", "timestamp": None},
        ],
        "solr": {
            "state": "up",
            "response_time_seconds": 0.0027,
            "checked_at": "2026-05-15 18:31:42",
            "error": "HTTP 400",
            "heap_usage_percent": 29.5,
            "cpu_percent": 0.11,
        },
        "autopsy_cpu_timeline": {"current": 0.0, "minus_5m": 0.0, "minus_15m": None},
    }

    _, html_body, _, _, _ = build_report_email(
        config=cfg,
        system_status="OK",
        events_last_period=0,
        uptime="1m 0s",
        recent_events=[],
        metrics_samples=[{"ts": 1.0, "cpu_percent": 10.0, "memory_percent": 20.0, "memory_used_bytes": 1, "memory_total_bytes": 2, "disk_free_bytes": 3, "disk_total_bytes": 4}],
        autopsy_pid=None,
        telemetry=telemetry,
    )

    assert "Current/Recent Module" in html_body
    assert "Solr | active | 2026-05-15 18:31:42" in html_body
    assert "Keyword/SOLR Activity" in html_body
    assert "Solr | active | 2026-05-15 18:31:42" in html_body
    assert "last warning=HTTP 400" in html_body
    assert "Solr is up; warning appears non-fatal/historical." in html_body


def test_report_builder_prefers_active_module_over_ingest_start(tmp_path):
    case_dir = tmp_path / "Case"
    case_dir.mkdir()
    (case_dir / "Case.aut").write_text("<autopsy/>", encoding="utf-8")
    cfg = MonitorConfig(case_dir=case_dir)
    telemetry = {
        "autopsy_db": {"exists": False, "size_bytes": None, "updated_at": None},
        "autopsy_log": {"exists": True, "size_bytes": 120, "updated_at": "2026-05-15 18:31:42", "line_count": 20},
        "case_size_bytes": 1024,
        "module_folders": [],
        "module_activity": [
            {"module": "Ingest", "state": "start", "line": "Starting ingest job", "timestamp": "2026-05-15 18:31:40"},
            {"module": "Keyword Search", "state": "active", "line": "KeywordSearchIngestModule.process", "timestamp": "2026-05-15 18:31:42"},
        ],
        "solr": {"state": "up", "response_time_seconds": 0.002, "checked_at": "2026-05-15 18:31:42", "error": None},
        "autopsy_cpu_timeline": {"current": 0.0, "minus_5m": 0.0, "minus_15m": None},
    }
    _, html_body, _, _, _ = build_report_email(
        config=cfg,
        system_status="OK",
        events_last_period=0,
        uptime="1m 0s",
        recent_events=[],
        metrics_samples=[{"ts": 1.0, "cpu_percent": 10.0, "memory_percent": 20.0, "memory_used_bytes": 1, "memory_total_bytes": 2, "disk_free_bytes": 3, "disk_total_bytes": 4}],
        autopsy_pid=None,
        telemetry=telemetry,
    )
    assert "Current/Recent Module" in html_body
    assert "Keyword Search | active | 2026-05-15 18:31:42" in html_body

