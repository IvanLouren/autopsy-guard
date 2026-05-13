"""Autopsy case validation logic."""

from __future__ import annotations

from pathlib import Path


def validate_case_dir(case_dir: Path) -> bool:
    """Check that a path looks like a valid Autopsy case directory.
    
    A valid case directory must contain a .aut descriptor file. In single-
    user installations a local `autopsy.db` will be present, but in
    multi-user (PostgreSQL) deployments the database is remote and
    `autopsy.db` is absent. To support both modes we accept a case that
    either has a local `autopsy.db` or a `Log/` directory.
    """
    if not case_dir.is_dir():
        return False
    if not any(case_dir.glob("*.aut")):
        return False

    has_local_db = (case_dir / "autopsy.db").exists()
    has_log_dir = (case_dir / "Log").is_dir()

    return has_local_db or has_log_dir
