"""Case/report telemetry collectors for periodic notifications."""

from __future__ import annotations

import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from autopsyguard.config import MonitorConfig
from autopsyguard.platform_utils import get_case_log_file
from autopsyguard.utils.i18n import tr


_MODULE_KEYWORDS = (
    "photorec",
    "carver",
    "keyword search",
    "keywordsearch",
    "solr",
    "email parser",
    "interesting files",
    "exif",
    "hash lookup",
    "extension mismatch",
)

_KEYWORD_MODULE_NAME: dict[str, str] = {
    "photorec": "PhotoRec Carver",
    "carver": "PhotoRec Carver",
    "keyword search": "Keyword Search",
    "keywordsearch": "Keyword Search",
    "solr": "Solr",
    "email parser": "Email Parser",
    "interesting files": "Interesting Files Identifier",
    "exif": "EXIF Parser",
    "hash lookup": "Hash Lookup",
    "extension mismatch": "Extension Mismatch Detector",
}


def _annotate_lines_with_timestamps(lines: list[str]) -> list[tuple[str, str | None]]:
    """Attach best-effort timestamp to each log line.

    Autopsy logs often emit a timestamped Java logger line followed by one or
    more non-timestamp continuation lines (e.g., INFO/WARNING text or stack
    trace frames). This propagates the most recent timestamp forward so module
    activity entries can keep temporal context.
    """
    annotated: list[tuple[str, str | None]] = []
    current_ts: str | None = None
    for raw in lines:
        line = raw.rstrip("\n")
        ts = _extract_line_timestamp(line)
        if ts:
            current_ts = ts
        annotated.append((line, ts or current_ts))
    return annotated


def _extract_line_timestamp(line: str) -> str | None:
    patterns = (
        r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})",
        r"(\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2})",
    )
    for pat in patterns:
        m = re.search(pat, line)
        if m:
            return m.group(1)
    return None


def _module_name_from_line(line: str) -> str | None:
    low = line.lower()

    if "found ingest module factory" in low:
        return None

    if "recent activity analysis" in low or ".recentactivity." in low:
        return "Recent Activity"
    if "keywordsearch" in low or "keyword search" in low or "kwsdataartifactingestmodule" in low:
        return "Keyword Search"
    if "solr" in low:
        return "Solr"
    if "photorec" in low:
        return "PhotoRec Carver"
    if "embedded file extractor" in low or "embeddedfileextractor" in low:
        return "Embedded File Extractor"
    if "email parser" in low or "emailparser" in low:
        return "Email Parser"
    if "yara ingest module" in low:
        return "YARA Analyzer"
    if "interesting files" in low:
        return "Interesting Files Identifier"
    if "hash lookup" in low:
        return "Hash Lookup"
    if "extension mismatch" in low:
        return "Extension Mismatch Detector"

    m = re.search(
        r"(?<!ingest\s)(?:\bmodule\b|\bmódulo\b)\s*[:=-]\s*([A-Za-z0-9 _\-/]{3,80})",
        line,
        flags=re.IGNORECASE,
    )
    if m:
        return m.group(1).strip()
    return None


def _state_from_line(low: str) -> str:
    if any(token in low for token in (" severe:", " error", "exception", "failed", "unable to")):
        return "error"
    if "warning" in low or "re-trying" in low:
        return "warning"
    if "start" in low or "starting" in low:
        return "start"
    if "finish" in low or "completed" in low:
        return "finish"
    return "active"


def _fmt_ts(ts: float | None) -> str | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def _safe_stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except OSError:
        return None


def _dir_size_bytes(path: Path) -> int:
    total = 0
    try:
        for root, _, files in os.walk(path):
            for name in files:
                f = Path(root) / name
                try:
                    total += f.stat().st_size
                except OSError:
                    continue
    except OSError:
        return 0
    return total


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def _tail_lines(path: Path, max_lines: int = 2000) -> list[str]:
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return lines
    return lines[-max_lines:]


def _extract_module_activity(lines: list[str]) -> list[dict[str, str]]:
    activities: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw, ts_ctx in reversed(_annotate_lines_with_timestamps(lines)):
        line = raw.strip()
        low = line.lower()
        if "found ingest module factory" in low:
            continue
        ts = _extract_line_timestamp(line) or ts_ctx

        if "starting ingest job" in low:
            key = ("ingest", "start")
            if key not in seen:
                seen.add(key)
                activities.append({"module": "Ingest", "state": "start", "line": line[:220], "timestamp": ts})
            continue
        if "finished all ingest tasks for ingest job" in low:
            key = ("ingest", "finish")
            if key not in seen:
                seen.add(key)
                activities.append({"module": "Ingest", "state": "finish", "line": line[:220], "timestamp": ts})
            continue

        module_name = _module_name_from_line(line)
        if module_name:
            state = _state_from_line(low)
            key = (module_name.lower(), state)
            if key not in seen:
                seen.add(key)
                activities.append({"module": module_name, "state": state, "line": line[:220], "timestamp": ts})
            continue

        for kw in _MODULE_KEYWORDS:
            if kw in low:
                state = _state_from_line(low)
                key = (kw, state)
                if key in seen:
                    continue
                seen.add(key)
                mod_name = _KEYWORD_MODULE_NAME.get(kw, kw.title())
                activities.append({"module": mod_name, "state": state, "line": line[:220], "timestamp": ts})
                break
    return activities[:20]


def _discover_module_dirs(case_dir: Path) -> list[Path]:
    candidates: list[Path] = []
    module_output = case_dir / "ModuleOutput"
    if module_output.is_dir():
        for child in sorted(module_output.iterdir()):
            if child.is_dir():
                candidates.append(child)
        if candidates:
            return candidates

    skip = {"log", ".autopsyguard", "reports", "export", "tmp", "temp"}
    try:
        for child in sorted(case_dir.iterdir()):
            if not child.is_dir():
                continue
            if child.name.lower() in skip:
                continue
            candidates.append(child)
    except OSError:
        pass
    return candidates


def _module_folder_summary(case_dir: Path) -> list[dict[str, Any]]:
    folders = _discover_module_dirs(case_dir)
    output: list[dict[str, Any]] = []
    for folder in folders:
        st = _safe_stat(folder)
        output.append(
            {
                "name": folder.name,
                "path": str(folder),
                "updated_at": _fmt_ts(st.st_mtime if st else None),
                "size_bytes": _dir_size_bytes(folder),
            }
        )
    output.sort(key=lambda x: x.get("name", "").lower())
    return output[:40]


def collect_case_telemetry(
    *,
    config: MonitorConfig,
    solr_status: Any | None,
    solr_metrics: Any | None,
    cpu_snapshots: dict[float, float | None],
) -> dict[str, Any]:
    """Collect case/log/module/Solr metadata for heartbeat report blocks."""
    case_dir = config.case_dir
    case_name = config.email_case_label.strip() if config.email_case_label else case_dir.name

    db_path = case_dir / "autopsy.db"
    db_st = _safe_stat(db_path)
    db_meta = {
        "path": str(db_path),
        "exists": db_st is not None,
        "size_bytes": int(db_st.st_size) if db_st else None,
        "updated_at": _fmt_ts(db_st.st_mtime if db_st else None),
        "note": None if db_st else tr(config, "db_missing"),
    }

    log_path = get_case_log_file(case_dir)
    log_st = _safe_stat(log_path)
    log_meta = {
        "path": str(log_path),
        "exists": log_st is not None,
        "size_bytes": int(log_st.st_size) if log_st else None,
        "updated_at": _fmt_ts(log_st.st_mtime if log_st else None),
        "line_count": _count_lines(log_path),
    }

    case_size = _dir_size_bytes(case_dir)
    module_folders = _module_folder_summary(case_dir)
    activity_lines = _tail_lines(log_path, max_lines=2500)
    module_activity = _extract_module_activity(activity_lines)

    solr_meta: dict[str, Any] = {
        "state": "unknown",
        "response_time_seconds": None,
        "checked_at": None,
        "error": None,
        "heap_usage_percent": None,
        "cpu_percent": None,
        "thread_count": None,
    }
    if solr_status is not None:
        solr_meta["state"] = "up" if getattr(solr_status, "is_up", False) else "down"
        solr_meta["response_time_seconds"] = getattr(solr_status, "response_time", None)
        solr_meta["checked_at"] = _fmt_ts(getattr(solr_status, "checked_at", None))
        solr_meta["error"] = getattr(solr_status, "error", None)
    if solr_metrics is not None:
        solr_meta["heap_usage_percent"] = getattr(solr_metrics, "heap_usage_percent", None)
        solr_meta["cpu_percent"] = getattr(solr_metrics, "cpu_percent", None)
        solr_meta["thread_count"] = getattr(solr_metrics, "thread_count", None)

    return {
        "case_name": case_name,
        "case_dir": str(case_dir),
        "autopsy_db": db_meta,
        "autopsy_log": log_meta,
        "case_size_bytes": case_size,
        "module_folders": module_folders,
        "module_activity": module_activity,
        "solr": solr_meta,
        "autopsy_cpu_timeline": {
            "current": cpu_snapshots.get(0.0),
            "minus_5m": cpu_snapshots.get(300.0),
            "minus_15m": cpu_snapshots.get(900.0),
            "captured_at": _fmt_ts(time.time()),
        },
    }
