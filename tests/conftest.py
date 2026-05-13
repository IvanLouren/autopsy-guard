"""Shared fixtures for AutopsyGuard tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from autopsyguard.config import MonitorConfig


@pytest.fixture()
def tmp_case_dir(tmp_path: Path) -> Path:
    """Create a minimal fake Autopsy case directory."""
    case = tmp_path / "TestCase"
    case.mkdir()
    # .aut file
    (case / "TestCase.aut").write_text("<autopsy/>", encoding="utf-8")
    # autopsy.db
    (case / "autopsy.db").write_bytes(b"")
    # Log directory
    log_dir = case / "Log"
    log_dir.mkdir()
    return case


@pytest.fixture()
def config(tmp_case_dir: Path) -> MonitorConfig:
    """Provide a MonitorConfig pointing at the fake case directory."""
    return MonitorConfig(
        case_dir=tmp_case_dir,
        autopsy_install_dir=None,
        poll_interval=1.0,
        hang_timeout=5.0,
        log_stale_timeout=5.0,
    )
