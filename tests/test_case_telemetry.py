from __future__ import annotations

import os
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
    assert telemetry["module_activity_summary"]
    first = telemetry["module_activity_summary"][0]
    assert "module_name" in first
    assert "last_state" in first
    assert "occurrence_count" in first


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


def test_module_folder_updated_at_uses_latest_nested_file_mtime(tmp_path: Path) -> None:
    case = tmp_path / "CaseD"
    case.mkdir()
    (case / "CaseD.aut").write_text("<autopsy/>", encoding="utf-8")
    log_dir = case / "Log"
    log_dir.mkdir()
    (log_dir / "autopsy.log.0").write_text("line\n", encoding="utf-8")
    mod_dir = case / "ModuleOutput" / "PhotoRec Carver"
    mod_dir.mkdir(parents=True)
    old_file = mod_dir / "old.txt"
    new_file = mod_dir / "new.txt"
    old_file.write_text("a", encoding="utf-8")
    new_file.write_text("b", encoding="utf-8")
    now = time.time()
    os.utime(old_file, (now - 7200, now - 7200))
    os.utime(new_file, (now - 120, now - 120))
    os.utime(mod_dir, (now - 9999, now - 9999))

    cfg = MonitorConfig(case_dir=case)
    telemetry = collect_case_telemetry(
        config=cfg,
        solr_status=None,
        solr_metrics=None,
        cpu_snapshots={0.0: None, 300.0: None, 900.0: None},
    )
    folders = telemetry["module_folders"]
    photorec = next((x for x in folders if x.get("name") == "PhotoRec Carver"), None)
    assert photorec is not None
    assert photorec.get("updated_at") is not None


def test_collect_case_telemetry_adds_folder_activity_signal_when_logs_sparse(tmp_path: Path) -> None:
    case = tmp_path / "CaseE"
    case.mkdir()
    (case / "CaseE.aut").write_text("<autopsy/>", encoding="utf-8")
    log_dir = case / "Log"
    log_dir.mkdir()
    (log_dir / "autopsy.log.0").write_text("INFO: unrelated startup line\n", encoding="utf-8")
    mod_dir = case / "ModuleOutput" / "PhotoRec Carver"
    mod_dir.mkdir(parents=True)
    artifact = mod_dir / "artifact.bin"
    artifact.write_bytes(b"123")
    now = time.time()
    os.utime(artifact, (now - 60, now - 60))

    cfg = MonitorConfig(case_dir=case)
    telemetry = collect_case_telemetry(
        config=cfg,
        solr_status=None,
        solr_metrics=None,
        cpu_snapshots={0.0: None, 300.0: None, 900.0: None},
    )
    activities = telemetry["module_activity"]
    folder_items = [
        item for item in activities
        if item.get("module") == "PhotoRec Carver" and "Folder growth signal" in str(item.get("line"))
    ]
    assert folder_items


def test_collect_case_telemetry_reads_rotated_case_logs_for_summary(tmp_path: Path) -> None:
    case = tmp_path / "CaseRot"
    case.mkdir()
    (case / "CaseRot.aut").write_text("<autopsy/>", encoding="utf-8")
    log_dir = case / "Log"
    log_dir.mkdir()
    (log_dir / "autopsy.log.1").write_text(
        "\n".join(
            [
                "2026-05-16 10:00:00 INFO: Starting ingest job in file batch mode (data source = Image.E01)",
                "2026-05-16 10:01:00 INFO: Recent Activity analysis of Image.E01 starting",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (log_dir / "autopsy.log.0").write_text(
        "\n".join(
            [
                "2026-05-16 10:03:00 INFO: Recent Activity analysis of Image.E01 finished",
                "2026-05-16 10:04:00 INFO: Finished all ingest tasks for ingest job (data source = Image.E01, ingest job ID = 1)",
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
    summary = telemetry["module_activity_summary"]
    ingest = next((x for x in summary if x.get("module_name") == "Ingest"), None)
    assert ingest is not None
    assert ingest.get("last_state") == "finish"
    recent = next((x for x in summary if x.get("module_name") == "Recent Activity"), None)
    assert recent is not None
    assert int(recent.get("occurrence_count") or 0) >= 2


def test_collect_case_telemetry_keyword_errors_are_aggregated_in_summary(tmp_path: Path) -> None:
    case = tmp_path / "CaseKey"
    case.mkdir()
    (case / "CaseKey.aut").write_text("<autopsy/>", encoding="utf-8")
    log_dir = case / "Log"
    log_dir.mkdir()
    (log_dir / "autopsy.log.0").write_text(
        "\n".join(
            [
                "2026-05-16 11:00:00 INFO: Starting ingest job in file batch mode (data source = Image.E01)",
                "2026-05-16 11:01:00 SEVERE: Keyword Search experienced an error during analysis while processing file A.dll (object ID = 10) (data source = Image.E01, ingest job ID = 1)",
                "2026-05-16 11:01:01 java.nio.charset.CoderMalfunctionError: java.lang.ArrayIndexOutOfBoundsException",
                "2026-05-16 11:01:02 java.lang.ArrayIndexOutOfBoundsException: Index -87 out of bounds",
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
    summary = telemetry["module_activity_summary"]
    kw = next((x for x in summary if x.get("module_name") == "Keyword Search"), None)
    assert kw is not None
    assert int(kw.get("occurrence_count") or 0) >= 3
    assert int(kw.get("error_count") or 0) >= 1

