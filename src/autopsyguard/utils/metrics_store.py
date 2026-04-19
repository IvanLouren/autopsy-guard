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
        # Use a small timeout to wait for transient locks and enable WAL journaling
        # for better concurrency and durability on busy systems.
        self._conn = sqlite3.connect(self._db_path, timeout=5.0)
        # Configure pragmatic PRAGMAs and run idempotent migrations
        self._configure_db()
        self._ensure_schema()

    def _configure_db(self) -> None:
        """Apply pragma settings that improve durability and reduce locking."""
        try:
            # Enable WAL journaling for better concurrency
            self._conn.execute("PRAGMA journal_mode=WAL")
            # Reasonable synchronous level for performance/durability tradeoff
            self._conn.execute("PRAGMA synchronous=NORMAL")
            # Set busy timeout via PRAGMA as well (milliseconds)
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.commit()
        except sqlite3.Error:
            # If PRAGMA fails, continue with defaults but log the event
            logger.debug("Failed to apply PRAGMA settings on metrics DB")

    @staticmethod
    def default_db_path(case_dir: Path) -> Path:
        """Return default metrics DB path under the case directory."""
        return case_dir / ".autopsyguard_state" / "metrics.db"

    def _ensure_schema(self) -> None:
        # Create base metrics table if missing
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

        # Ensure schema_version table exists and run migrations
        try:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
            )
            # If schema_version empty, insert version 1 (initial schema)
            cur = self._conn.execute("SELECT COUNT(*) FROM schema_version")
            count = cur.fetchone()[0]
            if count == 0:
                self._conn.execute("INSERT INTO schema_version (version) VALUES (1)")
                self._conn.commit()
        except sqlite3.Error:
            logger.debug("Could not ensure schema_version table for migrations")

        # Run idempotent migrations to bring DB up to current version
        try:
            self._run_migrations()
        except Exception as exc:
            logger.debug("Metrics DB migrations failed: %s", exc)

    def _get_table_columns(self, table: str) -> list[str]:
        cur = self._conn.execute(f"PRAGMA table_info({table})")
        return [row[1] for row in cur.fetchall()]

    def _current_schema_version(self) -> int:
        try:
            cur = self._conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")
            row = cur.fetchone()
            return int(row[0]) if row else 1
        except sqlite3.Error:
            return 1

    def _set_schema_version(self, v: int) -> None:
        try:
            # Simple append-only versioning for audit; keep single row for simplicity
            self._conn.execute("DELETE FROM schema_version")
            self._conn.execute("INSERT INTO schema_version (version) VALUES (?)", (v,))
            self._conn.commit()
        except sqlite3.Error:
            logger.debug("Could not update schema_version to %s", v)

    def _run_migrations(self) -> None:
        """Idempotent migrations to evolve metrics schema.

        Migration plan:
        - version 1: initial schema (created above)
        - version 2: add disk_read_bytes, disk_write_bytes columns
        """
        cur_ver = self._current_schema_version()

        # Migration to version 2: add disk_read_bytes/disk_write_bytes
        if cur_ver < 2:
            cols = self._get_table_columns("metrics")
            altered = False
            if "disk_read_bytes" not in cols:
                try:
                    self._conn.execute("ALTER TABLE metrics ADD COLUMN disk_read_bytes INTEGER DEFAULT 0")
                    altered = True
                except sqlite3.OperationalError:
                    logger.debug("disk_read_bytes column add failed or already exists")
            if "disk_write_bytes" not in cols:
                try:
                    self._conn.execute("ALTER TABLE metrics ADD COLUMN disk_write_bytes INTEGER DEFAULT 0")
                    altered = True
                except sqlite3.OperationalError:
                    logger.debug("disk_write_bytes column add failed or already exists")
            if altered:
                try:
                    self._conn.commit()
                except sqlite3.Error:
                    pass
            # Mark migration applied
            self._set_schema_version(2)

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
        # Discover which columns exist and build a SELECT dynamically so older DB
        # schemas (without disk_read/write) don't cause SQL errors.
        cols_info = self._conn.execute("PRAGMA table_info(metrics)").fetchall()
        existing_cols = [row[1] for row in cols_info]

        # Base columns we always want if present
        select_cols = [
            c for c in [
                "ts",
                "cpu_percent",
                "memory_percent",
                "memory_used_bytes",
                "memory_total_bytes",
                "disk_free_bytes",
                "disk_total_bytes",
            ] if c in existing_cols
        ]

        # Optional columns added in newer schemas
        optional_cols = ["disk_read_bytes", "disk_write_bytes", "autopsy_pid", "autopsy_rss_bytes"]
        for c in optional_cols:
            if c in existing_cols:
                select_cols.append(c)

        if not select_cols:
            return []

        sql = f"SELECT {', '.join(select_cols)} FROM metrics WHERE ts >= ? ORDER BY ts ASC"
        rows = self._conn.execute(sql, (since_ts,)).fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            entry: dict[str, Any] = {}
            for idx, col in enumerate(select_cols):
                entry[col] = row[idx]

            # Ensure consistent keys in the returned dict for callers
            for k in [
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
            ]:
                if k not in entry:
                    entry[k] = None

            results.append(entry)

        return results

    def close(self) -> None:
        """Close the database connection."""
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
