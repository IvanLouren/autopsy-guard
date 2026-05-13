"""Tests for platform path helpers."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from autopsyguard.platform_utils import get_autopsy_log_dir


def test_get_autopsy_log_dir_prefers_dev_profile_under_base_user_dir(tmp_path: Path) -> None:
    user_dir = tmp_path / ".autopsy"
    (user_dir / "var" / "log").mkdir(parents=True)
    (user_dir / "dev" / "var" / "log").mkdir(parents=True)

    with patch("autopsyguard.platform_utils.paths.get_autopsy_user_dir", return_value=user_dir):
        assert get_autopsy_log_dir() == user_dir / "dev" / "var" / "log"


def test_get_autopsy_log_dir_falls_back_to_parent_when_user_dir_is_dev(tmp_path: Path) -> None:
    user_dir = tmp_path / ".autopsy" / "dev"
    (user_dir.parent / "var" / "log").mkdir(parents=True)

    with patch("autopsyguard.platform_utils.paths.get_autopsy_user_dir", return_value=user_dir):
        assert get_autopsy_log_dir() == user_dir.parent / "var" / "log"
