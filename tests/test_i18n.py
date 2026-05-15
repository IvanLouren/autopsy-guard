from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from autopsyguard.config import MonitorConfig
from autopsyguard.utils.i18n import resolve_language, tr


def _cfg(tmp_path: Path) -> MonitorConfig:
    return MonitorConfig(case_dir=tmp_path)


def test_language_override_pt(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    cfg.language = "pt"
    assert resolve_language(cfg) == "pt"
    assert tr(cfg, "report_subject") == "Relatório de Estado"


def test_language_override_en(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    cfg.language = "en"
    assert resolve_language(cfg) == "en"
    assert tr(cfg, "report_subject") == "Status Report"


def test_language_auto_from_os_locale(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    cfg.language = "auto"
    with patch("autopsyguard.utils.i18n.locale.getlocale", return_value=("pt_PT", "UTF-8")):
        assert resolve_language(cfg) == "pt"
    with patch("autopsyguard.utils.i18n.locale.getlocale", return_value=("en_GB", "UTF-8")):
        assert resolve_language(cfg) == "en"
