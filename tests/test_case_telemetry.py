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
    cfg = MonitorConfig(case_dir=case)
    telemetry = collect_case_telemetry(
        config=cfg,
        solr_status=None,
        solr_metrics=None,
        cpu_snapshots={0.0: None, 300.0: None, 900.0: None},
    )
    assert telemetry["autopsy_db"]["exists"] is False
    assert "centralized" in telemetry["autopsy_db"]["note"].lower()


def test_collect_case_telemetry_extracts_recent_activity_and_timestamp_context(tmp_path: Path) -> None:
    case = tmp_path / "CaseB"
    case.mkdir()
    (case / "CaseB.aut").write_text("<autopsy/>", encoding="utf-8")
    log_dir = case / "Log"
    log_dir.mkdir()
    (log_dir / "autopsy.log.0").write_text(
        "\n".join(
            [
                "2026-05-15 18:25:31.044 org.sleuthkit.autopsy.ingest.IngestManager startIngestJob",
                "INFO: Starting ingest job 0 at 1778865931044",
                "2026-05-15 18:25:34.066 org.sleuthkit.autopsy.ingest.DataSourceIngestPipeline$DataSourcePipelineModule process",
                "INFO: Recent Activity analysis of Laptop1Final.E01 starting",
                "2026-05-15 18:36:30.104 org.sleuthkit.autopsy.keywordsearch.Server$Collection sendBufferedDocs",
                "WARNING: Unable to send document batch to Solr. Re-trying...",
                "org.sleuthkit.autopsy.keywordsearch.KeywordSearchIngestModule.process(KeywordSearchIngestModule.java:456)",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cfg = MonitorConfig(case_dir=case)
    telemetry = collect_case_telemetry(
        config=cfg,
        solr_status=None,
        solr_metrics=None,
        cpu_snapshots={0.0: None, 300.0: None, 900.0: None},
    )
    modules = [a["module"] for a in telemetry["module_activity"]]
    assert "Recent Activity" in modules
    assert "Keyword Search" in modules
    kw_items = [a for a in telemetry["module_activity"] if a["module"] == "Keyword Search"]
    assert kw_items and kw_items[0].get("timestamp") == "2026-05-15 18:36:30"


def test_collect_case_telemetry_ignores_factory_lines_and_yara_message_noise(tmp_path: Path) -> None:
    case = tmp_path / "CaseC"
    case.mkdir()
    (case / "CaseC.aut").write_text("<autopsy/>", encoding="utf-8")
    log_dir = case / "Log"
    log_dir.mkdir()
    (log_dir / "autopsy.log.0").write_text(
        "\n".join(
            [
                "2026-05-15 18:24:54.489 org.sleuthkit.autopsy.ingest.IngestModuleFactoryLoader addFactory",
                "INFO: Found ingest module factory: name = PhotoRec Carver, version = 7.0",
                "2026-05-15 18:25:33.480 org.sleuthkit.autopsy.modules.yara.YaraIngestModule startUp",
                "INFO: YARA ingest module: No rule set was selected for this ingest job.",
                "2026-05-15 18:25:34.066 org.sleuthkit.autopsy.ingest.DataSourceIngestPipeline$DataSourcePipelineModule process",
                "INFO: Recent Activity analysis of Laptop1Final.E01 starting",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    cfg = MonitorConfig(case_dir=case)
    telemetry = collect_case_telemetry(
        config=cfg,
        solr_status=None,
        solr_metrics=None,
        cpu_snapshots={0.0: None, 300.0: None, 900.0: None},
    )

    modules = [a["module"] for a in telemetry["module_activity"]]
    assert "Recent Activity" in modules
    assert "YARA Analyzer" in modules
    assert "No rule set was selected for this ingest job" not in modules
    assert "PhotoRec Carver" not in modules

