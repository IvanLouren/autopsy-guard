from __future__ import annotations

import time
from pathlib import Path

from autopsyguard.config import MonitorConfig
from autopsyguard.utils.case_telemetry import collect_case_telemetry
from autopsyguard.utils.solr_health import SolrStatus


def _make_case(tmp_path: Path) -> Path:
    case = tmp_path / "CaseA"
    case.mkdir()
    (case / "CaseA.aut").write_text("<autopsy/>", encoding="utf-8")
    (case / "autopsy.db").write_bytes(b"x" * 100)
    log_dir = case / "Log"
    log_dir.mkdir()
    (log_dir / "autopsy.log.0").write_text(
        "Starting ingest job\nKeyword Search started\nFinished all ingest tasks for ingest job\n",
        encoding="utf-8",
    )
    mod = case / "ModuleOutput"
    mod.mkdir()
    (mod / "PhotoRec Carver").mkdir()
    (mod / "PhotoRec Carver" / "out.txt").write_text("data", encoding="utf-8")
    return case


def test_collect_case_telemetry_with_local_db(tmp_path: Path) -> None:
    case = _make_case(tmp_path)
    cfg = MonitorConfig(case_dir=case)
    status = SolrStatus(is_up=True, response_time=0.25, checked_at=time.time(), error=None)
    telemetry = collect_case_telemetry(
        config=cfg,
        solr_status=status,
        solr_metrics=None,
        cpu_snapshots={0.0: 44.0, 300.0: 33.0, 900.0: 22.0},
    )

    assert telemetry["case_name"] == "CaseA"
    assert telemetry["autopsy_db"]["exists"] is True
    assert telemetry["autopsy_log"]["line_count"] >= 3
    assert telemetry["case_size_bytes"] > 0
    assert telemetry["solr"]["state"] == "up"
    assert telemetry["autopsy_cpu_timeline"]["minus_5m"] == 33.0
    assert any("PhotoRec Carver" in m["name"] for m in telemetry["module_folders"])
    assert any("Keyword Search" in a["module"] for a in telemetry["module_activity"])


def test_collect_case_telemetry_without_local_db(tmp_path: Path) -> None:
    case = tmp_path / "CaseNoDb"
    case.mkdir()
    (case / "CaseNoDb.aut").write_text("<autopsy/>", encoding="utf-8")
    log_dir = case / "Log"
    log_dir.mkdir()
    (log_dir / "autopsy.log.0").write_text("line\n", encoding="utf-8")
    cfg = MonitorConfig(case_dir=case, language="en")
    telemetry = collect_case_telemetry(
        config=cfg,
        solr_status=None,
        solr_metrics=None,
        cpu_snapshots={0.0: None, 300.0: None, 900.0: None},
    )
    assert telemetry["autopsy_db"]["exists"] is False
    assert "centralized" in telemetry["autopsy_db"]["note"].lower()
