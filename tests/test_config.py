"""Tests for YAML-backed configuration loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from autopsyguard.config import MonitorConfig


def test_from_sources_loads_yaml_values(tmp_path: Path) -> None:
    # Create the case directory so validation passes
    case_dir = tmp_path / "CaseA"
    case_dir.mkdir()
    
    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "\n".join(
            [
                "case_dir: ./CaseA",
                "poll_interval: 3.5",
                "hang_timeout: 42",
                "error_patterns:",
                "  - FATAL",
                "  - Exception",
            ]
        ),
        encoding="utf-8",
    )

    config = MonitorConfig.from_sources(yaml_path=cfg)

    assert config.case_dir == (tmp_path / "CaseA").resolve()
    assert config.poll_interval == 3.5
    assert config.hang_timeout == 42
    assert config.error_patterns == ["FATAL", "Exception"]


def test_from_sources_cli_overrides_yaml(tmp_path: Path) -> None:
    # Create the case directories so validation passes
    (tmp_path / "CaseA").mkdir()
    (tmp_path / "CaseB").mkdir()
    
    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "\n".join(
            [
                "case_dir: ./CaseA",
                "poll_interval: 10",
            ]
        ),
        encoding="utf-8",
    )

    config = MonitorConfig.from_sources(
        yaml_path=cfg,
        overrides={"poll_interval": 1.0, "case_dir": tmp_path / "CaseB"},
    )

    assert config.poll_interval == 1.0
    assert config.case_dir == tmp_path / "CaseB"


def test_from_sources_requires_case_dir() -> None:
    with pytest.raises(ValueError, match="Missing required setting 'case_dir'"):
        MonitorConfig.from_sources()


def test_from_sources_rejects_unknown_key(tmp_path: Path) -> None:
    # Create the case directory
    (tmp_path / "CaseA").mkdir()
    
    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "\n".join(
            [
                "case_dir: ./CaseA",
                "unknown_setting: 1",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unknown config key"):
        MonitorConfig.from_sources(yaml_path=cfg)


def test_from_sources_loads_solr_settings(tmp_path: Path) -> None:
    # Create the case directory
    (tmp_path / "CaseA").mkdir()
    
    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "\n".join(
            [
                "case_dir: ./CaseA",
                "solr_port: 24000",
                "solr_timeout_seconds: 8.0",
                "solr_slow_threshold_seconds: 3.0",
                "solr_slow_count_threshold: 4",
                "solr_heap_usage_warning: 80.0",
                "solr_heap_usage_critical: 93.0",
                "solr_cpu_warning: 88.0",
            ]
        ),
        encoding="utf-8",
    )

    config = MonitorConfig.from_sources(yaml_path=cfg)

    assert config.solr_port == 24000
    assert config.solr_timeout_seconds == 8.0
    assert config.solr_slow_threshold_seconds == 3.0
    assert config.solr_slow_count_threshold == 4
    assert config.solr_heap_usage_warning == 80.0
    assert config.solr_heap_usage_critical == 93.0
    assert config.solr_cpu_warning == 88.0


def test_from_sources_allows_multicore_process_cpu_threshold_over_100(tmp_path: Path) -> None:
    (tmp_path / "CaseA").mkdir()

    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "\n".join(
            [
                "case_dir: ./CaseA",
                "cpu_warning_percent: 250.0",
            ]
        ),
        encoding="utf-8",
    )

    config = MonitorConfig.from_sources(yaml_path=cfg)
    assert config.cpu_warning_percent == 250.0


def test_from_sources_rejects_per_core_cpu_threshold_over_100(tmp_path: Path) -> None:
    (tmp_path / "CaseA").mkdir()

    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "\n".join(
            [
                "case_dir: ./CaseA",
                "cpu_per_core_warning_percent: 101.0",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="cpu_per_core_warning_percent"):
        MonitorConfig.from_sources(yaml_path=cfg)


def test_from_sources_loads_telegram_settings(tmp_path: Path) -> None:
    (tmp_path / "CaseA").mkdir()

    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "\n".join(
            [
                "case_dir: ./CaseA",
                "telegram_enabled: true",
                "telegram_user: '@myusername'",
            ]
        ),
        encoding="utf-8",
    )

    config = MonitorConfig.from_sources(yaml_path=cfg)
    assert config.telegram_enabled is True
    assert config.telegram_user == "@myusername"


def test_from_sources_ignores_legacy_oauth_keys_with_warning(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    (tmp_path / "CaseA").mkdir()

    cfg = tmp_path / "config.yml"
    cfg.write_text(
        "\n".join(
            [
                "case_dir: ./CaseA",
                "smtp_host: smtp.gmail.com",
                "smtp_auth_mode: oauth",
                "smtp_oauth_provider: google",
                "smtp_oauth_client_id: abc",
                "smtp_oauth_client_secret: def",
                "smtp_oauth_token_file: token.json",
            ]
        ),
        encoding="utf-8",
    )

    with caplog.at_level("WARNING"):
        config = MonitorConfig.from_sources(yaml_path=cfg)

    assert config.smtp_host == "smtp.gmail.com"
    assert "Deprecated config key(s) ignored" in caplog.text
