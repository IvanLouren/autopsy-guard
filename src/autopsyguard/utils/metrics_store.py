"""SQLite-backed metrics storage for reporting and charts."""

from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

import psutil

from autopsyguard.utils.process_utils import find_autopsy_pid

logger = logging.getLogger(__name__)


class MetricsStore:
    """Store periodic system and Autopsy metrics in SQLite."""

    def __init__(self, *, case_dir: Path, db_path: Path | None = None) -> None:
        self._case_dir = case_dir
        self._db_path = db_path or self.default_db_path(case_dir)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path)
        self._ensure_schema()

    @staticmethod
    def default_db_path(case_dir: Path) -> Path:
        """Return default metrics DB path under the case directory."""
        return case_dir / ".autopsyguard_state" / "metrics.db"

    def _ensure_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS metrics (
                ts REAL NOT NULL,
                cpu_percent REAL NOT NULL,
                memory_percent REAL NOT NULL,
                memory_used_bytes INTEGER NOT NULL,
                memory_total_bytes INTEGER NOT NULL,
                disk_free_bytes INTEGER NOT NULL,
                disk_total_bytes INTEGER NOT NULL,
                autopsy_pid INTEGER,
                autopsy_rss_bytes INTEGER
            )
            """
        )
        self._conn.commit()
        # Ensure disk I/O columns exist for backward-compatible schema migration
        try:
            self._conn.execute(
                "ALTER TABLE metrics ADD COLUMN disk_read_bytes INTEGER DEFAULT 0"
            )
            self._conn.execute(
                "ALTER TABLE metrics ADD COLUMN disk_write_bytes INTEGER DEFAULT 0"
            )
            self._conn.commit()
        except sqlite3.OperationalError:
            # Column already exists or other benign error — ignore
            pass

    def record_sample(self) -> None:
        """Capture a metrics sample and persist it."""
        try:
            timestamp = time.time()
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(str(self._case_dir))
            disk_io = psutil.disk_io_counters()

            autopsy_pid = find_autopsy_pid()
            autopsy_rss = None
            if autopsy_pid is not None:
                try:
                    proc = psutil.Process(autopsy_pid)
                    autopsy_rss = proc.memory_info().rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    autopsy_pid = None
                    autopsy_rss = None

            # Desired mapping of column -> value (covers both old and new schemas)
            value_map = {
                "ts": timestamp,
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_used_bytes": int(memory.used),
                "memory_total_bytes": int(memory.total),
                "disk_free_bytes": int(disk.free),
                "disk_total_bytes": int(disk.total),
                "disk_read_bytes": int(disk_io.read_bytes) if disk_io is not None else 0,
                "disk_write_bytes": int(disk_io.write_bytes) if disk_io is not None else 0,
                "autopsy_pid": autopsy_pid,
                "autopsy_rss_bytes": int(autopsy_rss) if autopsy_rss is not None else None,
            }

            # Inspect current table columns and insert only those present
            cols_info = self._conn.execute("PRAGMA table_info(metrics)").fetchall()
            existing_cols = [row[1] for row in cols_info]
            insert_cols = [c for c in [
                "ts",
                "cpu_percent",
                "memory_percent",
                "memory_used_bytes",
                "memory_total_bytes",
                "disk_free_bytes",
                "disk_total_bytes",
                "disk_read_bytes",
                "disk_write_bytes",
                "autopsy_pid",
                "autopsy_rss_bytes",
            ] if c in existing_cols]

            placeholders = ",".join(["?" for _ in insert_cols])
            sql = f"INSERT INTO metrics ({','.join(insert_cols)}) VALUES ({placeholders})"
            values = [value_map[c] for c in insert_cols]

            self._conn.execute(sql, tuple(values))
            self._conn.commit()
        except Exception as exc:
            logger.debug("Metrics sample failed: %s", exc)

    def fetch_samples(self, *, since_ts: float) -> list[dict[str, Any]]:
        """Fetch samples since a Unix timestamp."""
        rows = self._conn.execute(
            """
            SELECT ts, cpu_percent, memory_percent, memory_used_bytes,
                   memory_total_bytes, disk_read_bytes, disk_write_bytes, autopsy_pid, autopsy_rss_bytes
            FROM metrics
            WHERE ts >= ?
            ORDER BY ts ASC
            """,
            (since_ts,),
        ).fetchall()

        return [
            {
                "ts": row[0],
                "cpu_percent": row[1],
                "memory_percent": row[2],
                "memory_used_bytes": row[3],
                "memory_total_bytes": row[4],
                "disk_read_bytes": row[5],
                "disk_write_bytes": row[6],
                "autopsy_pid": row[7],
                "autopsy_rss_bytes": row[8],
            }
            for row in rows
        ]

    def close(self) -> None:
        """Close the database connection."""
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
