from __future__ import annotations

from pathlib import Path


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_setup_wizards_do_not_emit_oauth_config_keys() -> None:
    ps1 = _read("scripts/setup-autopsyguard.ps1")
    sh = _read("scripts/setup-autopsyguard.sh")

    for text in (ps1, sh):
        assert "smtp_oauth_" not in text
        assert "smtp_auth_mode" not in text
        assert "language: 'auto'" in text
        assert "case_name_source: 'real'" in text


def test_readme_has_no_oauth_setup_appendix() -> None:
    readme = _read("README.md")
    assert "Advanced Appendix: OAuth SMTP" not in readme

