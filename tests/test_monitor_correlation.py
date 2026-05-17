from __future__ import annotations

from autopsyguard.models import CrashEvent, CrashType, Severity
from autopsyguard.monitor import Monitor


def _ev(crash_type: CrashType, severity: Severity, message: str) -> CrashEvent:
    return CrashEvent(crash_type=crash_type, severity=severity, message=message)


def test_correlates_multi_detector_burst_into_single_incident(config) -> None:
    monitor = Monitor(config)
    monitor._correlation_window_seconds = 10.0

    e1 = _ev(CrashType.OUT_OF_MEMORY, Severity.CRITICAL, "OOM in JVM")
    e2 = _ev(CrashType.HANG, Severity.WARNING, "Autopsy appears stuck")
    e3 = _ev(CrashType.SOLR_CRASH, Severity.CRITICAL, "Solr service unavailable")

    ready1 = monitor._collect_alert_notifications([e1], now=100.0)
    assert len(ready1) == 1
    assert ready1[0].crash_type == CrashType.OUT_OF_MEMORY
    assert monitor._collect_alert_notifications([e2], now=104.0) == []

    ready3 = monitor._collect_alert_notifications([e3], now=108.0)
    assert len(ready3) == 1
    incident = ready3[0]
    assert incident.crash_type == CrashType.CORRELATED_INCIDENT
    assert incident.severity == Severity.CRITICAL
    assert incident.details["event_count"] == 2
    assert set(incident.details["event_types"]) == {
        "HANG",
        "SOLR_CRASH",
    }

    ready = monitor._collect_alert_notifications([], now=111.0)
    assert ready == []


def test_single_alert_type_is_not_wrapped_as_incident(config) -> None:
    monitor = Monitor(config)
    monitor._correlation_window_seconds = 10.0

    e1 = _ev(CrashType.HANG, Severity.WARNING, "Autopsy appears stuck")

    assert monitor._collect_alert_notifications([e1], now=200.0) == []
    ready = monitor._collect_alert_notifications([], now=211.0)

    assert len(ready) == 1
    assert ready[0].crash_type == CrashType.HANG
    assert ready[0].message == e1.message


def test_alerts_in_different_windows_are_not_merged(config) -> None:
    monitor = Monitor(config)
    monitor._correlation_window_seconds = 10.0

    e1 = _ev(CrashType.OUT_OF_MEMORY, Severity.CRITICAL, "OOM in JVM")
    e2 = _ev(CrashType.SOLR_CRASH, Severity.CRITICAL, "Solr unavailable")

    first = monitor._collect_alert_notifications([e1], now=300.0)
    assert len(first) == 1
    assert first[0].crash_type == CrashType.OUT_OF_MEMORY

    second = monitor._collect_alert_notifications([e2], now=312.0)
    assert len(second) == 1
    assert second[0].crash_type == CrashType.SOLR_CRASH


def test_duplicate_signature_is_suppressed_within_cooldown(config) -> None:
    monitor = Monitor(config)
    monitor._critical_reminder_seconds = 120.0

    event = _ev(CrashType.SOLR_CRASH, Severity.CRITICAL, "Solr refused connection")
    first = monitor._collect_alert_notifications([event], now=500.0)
    assert len(first) == 1

    duplicate = monitor._collect_alert_notifications([event], now=560.0)
    assert duplicate == []

    after_reminder = monitor._collect_alert_notifications([event], now=650.0)
    assert len(after_reminder) == 1

