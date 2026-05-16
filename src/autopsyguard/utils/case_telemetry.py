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
from autopsyguard.utils.messages import tr


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

_INGEST_START_PATTERN = re.compile(r"starting ingest job", re.IGNORECASE)
_INGEST_FINISH_PATTERN = re.compile(r"finished all ingest tasks for ingest job", re.IGNORECASE)
_INGEST_JOB_ID_PATTERN = re.compile(r"ingest job id\s*=\s*(\d+)", re.IGNORECASE)
_DATA_SOURCE_PATTERN = re.compile(r"data source\s*=\s*([^\),]+)", re.IGNORECASE)


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


def _dir_latest_file_mtime(path: Path) -> float | None:
    latest: float | None = None
    try:
        for root, _, files in os.walk(path):
            for name in files:
                f = Path(root) / name
                try:
                    mtime = f.stat().st_mtime
                except OSError:
                    continue
                if latest is None or mtime > latest:
                    latest = mtime
    except OSError:
        return None
    return latest


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def _parse_activity_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except Exception:
            continue
    return None


def _discover_case_log_files(case_dir: Path) -> list[Path]:
    log_dir = case_dir / "Log"
    if not log_dir.is_dir():
        return []
    files: list[Path] = []
    try:
        for child in log_dir.iterdir():
            if not child.is_file():
                continue
            if not child.name.lower().startswith("autopsy.log."):
                continue
            files.append(child)
    except OSError:
        return []

    def _rotation_index(name: str) -> int:
        try:
            return int(name.rsplit(".", 1)[1])
        except Exception:
            return -1

    files.sort(
        key=lambda p: (
            _safe_stat(p).st_mtime if _safe_stat(p) else 0.0,
            -_rotation_index(p.name),
            p.name.lower(),
        )
    )
    return files


def _read_case_log_lines(case_dir: Path) -> list[str]:
    all_lines: list[str] = []
    for path in _discover_case_log_files(case_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        all_lines.extend(text.splitlines())
    return all_lines


def _extract_first(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    if not m:
        return None
    value = (m.group(1) or "").strip()
    return value or None


def _extract_module_activity_raw(lines: list[str]) -> list[dict[str, str]]:
    activities: list[dict[str, str]] = []
    current_context = "unscoped"
    ingest_session = 0
    last_module_by_context: dict[str, str] = {}

    for raw, ts_ctx in _annotate_lines_with_timestamps(lines):
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if "found ingest module factory" in low:
            continue
        ts = _extract_line_timestamp(line) or ts_ctx

        data_source = _extract_first(_DATA_SOURCE_PATTERN, line)
        job_id = _extract_first(_INGEST_JOB_ID_PATTERN, line)

        if _INGEST_START_PATTERN.search(low):
            ingest_session += 1
            current_context = f"s{ingest_session}|j={job_id or 'na'}|d={data_source or 'na'}"
            activities.append(
                {
                    "module": "Ingest",
                    "state": "start",
                    "line": line[:220],
                    "timestamp": ts or "",
                    "context": current_context,
                }
            )
            continue
        if _INGEST_FINISH_PATTERN.search(low):
            activities.append(
                {
                    "module": "Ingest",
                    "state": "finish",
                    "line": line[:220],
                    "timestamp": ts or "",
                    "context": current_context,
                }
            )
            continue

        module_name = _module_name_from_line(line)
        if module_name is None:
            for kw in _MODULE_KEYWORDS:
                if kw in low:
                    module_name = _KEYWORD_MODULE_NAME.get(kw, kw.title())
                    break
        if module_name is None and any(token in low for token in ("exception", "error", "severe")):
            module_name = last_module_by_context.get(current_context)
        if module_name is None:
            continue

        last_module_by_context[current_context] = module_name
        activities.append(
            {
                "module": module_name,
                "state": _state_from_line(low),
                "line": line[:220],
                "timestamp": ts or "",
                "context": current_context,
            }
        )
    return activities


def _select_latest_context(raw_activity: list[dict[str, str]]) -> str | None:
    if not raw_activity:
        return None
    by_context: dict[str, tuple[float, int]] = {}
    for idx, item in enumerate(raw_activity):
        context = str(item.get("context") or "unscoped")
        ts = _parse_activity_ts(item.get("timestamp"))
        epoch = ts.timestamp() if ts else -1.0
        prev = by_context.get(context)
        marker = (epoch, idx)
        if prev is None or marker > prev:
            by_context[context] = marker
    if not by_context:
        return None
    return max(by_context.items(), key=lambda it: it[1])[0]


def _confidence_from_epoch(last_epoch: float | None, *, now_ts: float) -> str:
    if last_epoch is None:
        return "stale"
    age_seconds = now_ts - last_epoch
    if age_seconds <= 300:
        return "current"
    if age_seconds <= 1800:
        return "recent"
    return "stale"


def _build_module_activity_summary(
    raw_activity: list[dict[str, str]],
    *,
    now_ts: float,
) -> list[dict[str, Any]]:
    if not raw_activity:
        return []
    latest_context = _select_latest_context(raw_activity)
    scoped = [x for x in raw_activity if str(x.get("context") or "unscoped") == latest_context]
    if not scoped:
        scoped = list(raw_activity)

    summary: dict[str, dict[str, Any]] = {}
    for idx, item in enumerate(scoped):
        module_name = str(item.get("module") or "").strip()
        if not module_name:
            continue
        key = module_name.lower()
        state = str(item.get("state") or "active")
        line = str(item.get("line") or "")[:220]
        ts_obj = _parse_activity_ts(item.get("timestamp"))
        ts_epoch = ts_obj.timestamp() if ts_obj else None
        ts_text = ts_obj.strftime("%Y-%m-%d %H:%M:%S") if ts_obj else None

        row = summary.get(key)
        if row is None:
            summary[key] = {
                "module_name": module_name,
                "module": module_name,
                "first_seen": ts_text,
                "last_seen": ts_text,
                "last_state": state,
                "occurrence_count": 1,
                "error_count": 1 if state == "error" else 0,
                "sample_last_line": line,
                "_first_epoch": ts_epoch,
                "_last_epoch": ts_epoch,
                "_last_index": idx,
            }
            continue

        row["occurrence_count"] = int(row["occurrence_count"]) + 1
        if state == "error":
            row["error_count"] = int(row["error_count"]) + 1
        first_epoch = row.get("_first_epoch")
        last_epoch = row.get("_last_epoch")
        if ts_epoch is not None:
            if first_epoch is None or ts_epoch < first_epoch:
                row["_first_epoch"] = ts_epoch
                row["first_seen"] = ts_text
            if last_epoch is None or ts_epoch >= last_epoch:
                row["_last_epoch"] = ts_epoch
                row["last_seen"] = ts_text
                row["last_state"] = state
                row["sample_last_line"] = line
                row["_last_index"] = idx
        else:
            if row.get("_last_index", -1) <= idx:
                row["last_state"] = state
                row["sample_last_line"] = line
                row["_last_index"] = idx

    output: list[dict[str, Any]] = []
    for row in summary.values():
        row["confidence"] = _confidence_from_epoch(row.get("_last_epoch"), now_ts=now_ts)
        row.pop("_first_epoch", None)
        row.pop("_last_epoch", None)
        row.pop("_last_index", None)
        output.append(row)

    output.sort(
        key=lambda x: (
            _parse_activity_ts(x.get("last_seen")).timestamp() if _parse_activity_ts(x.get("last_seen")) else -1.0,
            str(x.get("module_name") or "").lower(),
        ),
        reverse=True,
    )
    return output[:40]


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
        latest_file_mtime = _dir_latest_file_mtime(folder)
        updated_mtime = latest_file_mtime if latest_file_mtime is not None else (st.st_mtime if st else None)
        output.append(
            {
                "name": folder.name,
                "path": str(folder),
                "updated_at": _fmt_ts(updated_mtime),
                "size_bytes": _dir_size_bytes(folder),
                "_latest_file_mtime": latest_file_mtime,
            }
        )
    output.sort(key=lambda x: x.get("name", "").lower())
    return output[:40]


def _merge_folder_activity_fallback(
    summary: list[dict[str, Any]],
    module_folders: list[dict[str, Any]],
    *,
    now_ts: float,
) -> list[dict[str, Any]]:
    merged = list(summary)
    index: dict[str, dict[str, Any]] = {
        str(item.get("module_name") or item.get("module") or "").strip().lower(): item
        for item in merged
    }
    for folder in module_folders:
        name = str(folder.get("name") or "").strip()
        if not name:
            continue
        key = name.lower()
        latest_file_mtime = folder.get("_latest_file_mtime")
        try:
            latest_ts = float(latest_file_mtime) if latest_file_mtime is not None else None
        except Exception:
            latest_ts = None
        if latest_ts is None:
            continue
        age_seconds = now_ts - latest_ts
        if age_seconds > 1800.0:
            continue
        row = index.get(key)
        if row is None:
            ts_text = _fmt_ts(latest_ts)
            merged.append(
                {
                    "module_name": name,
                    "module": name,
                    "first_seen": ts_text,
                    "last_seen": ts_text,
                    "last_state": "active",
                    "occurrence_count": 1,
                    "error_count": 0,
                    "sample_last_line": f"Folder growth signal: size={int(folder.get('size_bytes') or 0)} bytes",
                    "confidence": _confidence_from_epoch(latest_ts, now_ts=now_ts),
                }
            )
            continue
        row_last_ts = _parse_activity_ts(row.get("last_seen"))
        if row_last_ts is None or latest_ts > row_last_ts.timestamp():
            row["last_seen"] = _fmt_ts(latest_ts)
            row["last_state"] = "active"
            row["sample_last_line"] = f"Folder growth signal: size={int(folder.get('size_bytes') or 0)} bytes"
            row["confidence"] = _confidence_from_epoch(latest_ts, now_ts=now_ts)

    merged.sort(
        key=lambda x: (
            _parse_activity_ts(x.get("last_seen")).timestamp() if _parse_activity_ts(x.get("last_seen")) else -1.0,
            str(x.get("module_name") or "").lower(),
        ),
        reverse=True,
    )
    return merged[:40]


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
    now_ts = time.time()
    activity_lines = _read_case_log_lines(case_dir)
    module_activity_raw = _extract_module_activity_raw(activity_lines)
    module_activity_summary = _build_module_activity_summary(module_activity_raw, now_ts=now_ts)
    module_activity_summary = _merge_folder_activity_fallback(
        module_activity_summary,
        module_folders,
        now_ts=now_ts,
    )
    module_activity = [
        {
            "module": str(item.get("module_name") or item.get("module") or "N/A"),
            "state": str(item.get("last_state") or "active"),
            "line": str(item.get("sample_last_line") or "")[:220],
            "timestamp": item.get("last_seen"),
            "occurrence_count": int(item.get("occurrence_count") or 1),
            "error_count": int(item.get("error_count") or 0),
            "confidence": str(item.get("confidence") or "stale"),
        }
        for item in module_activity_summary
    ]

    # Strip internal helper fields from public telemetry payload.
    public_module_folders: list[dict[str, Any]] = []
    for folder in module_folders:
        clean = dict(folder)
        clean.pop("_latest_file_mtime", None)
        public_module_folders.append(clean)

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
        "module_folders": public_module_folders,
        "module_activity_summary": module_activity_summary,
        "module_activity_raw": module_activity_raw[:120],
        "module_activity": module_activity,
        "solr": solr_meta,
        "autopsy_cpu_timeline": {
            "current": cpu_snapshots.get(0.0),
            "minus_5m": cpu_snapshots.get(300.0),
            "minus_15m": cpu_snapshots.get(900.0),
            "captured_at": _fmt_ts(time.time()),
        },
    }

