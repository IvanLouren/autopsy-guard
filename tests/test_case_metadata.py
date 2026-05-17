from __future__ import annotations

from pathlib import Path

from autopsyguard.config import MonitorConfig
from autopsyguard.notifiers.email.templates import get_case_label
from autopsyguard.utils.case_metadata import read_autopsy_case_display_name


def _write_aut(case_dir: Path, xml: str) -> None:
    (case_dir / "Evidence.aut").write_text(xml, encoding="utf-8")


def test_read_display_name_prefers_display_name(tmp_path: Path) -> None:
    case = tmp_path / "MyCase"
    case.mkdir()
    _write_aut(
        case,
        """<?xml version="1.0" encoding="UTF-8"?>
<CaseMetadata>
  <Case>
    <Name>Internal</Name>
    <DisplayName>Evidence Case 2025-001</DisplayName>
  </Case>
</CaseMetadata>
""",
    )
    assert read_autopsy_case_display_name(case) == "Evidence Case 2025-001"


def test_read_display_name_falls_back_to_name(tmp_path: Path) -> None:
    case = tmp_path / "MyCase"
    case.mkdir()
    _write_aut(
        case,
        """<?xml version="1.0" encoding="UTF-8"?>
<CaseMetadata>
  <Case>
    <Name>Legacy Case Name</Name>
  </Case>
</CaseMetadata>
""",
    )
    assert read_autopsy_case_display_name(case) == "Legacy Case Name"


def test_get_case_label_uses_aut_display_name(tmp_path: Path) -> None:
    case = tmp_path / "folder-only-name"
    case.mkdir()
    (case / "folder-only-name.aut").write_text(
        "<CaseMetadata><Case><DisplayName>Autopsy UI Name</DisplayName></Case></CaseMetadata>",
        encoding="utf-8",
    )
    (case / "autopsy.db").write_bytes(b"")
    config = MonitorConfig(case_dir=case)
    assert get_case_label(config) == "Autopsy UI Name"


def test_get_case_label_prefers_email_override(tmp_path: Path) -> None:
    case = tmp_path / "folder-only-name"
    case.mkdir()
    (case / "folder-only-name.aut").write_text(
        "<CaseMetadata><Case><DisplayName>Autopsy UI Name</DisplayName></Case></CaseMetadata>",
        encoding="utf-8",
    )
    (case / "autopsy.db").write_bytes(b"")
    config = MonitorConfig(case_dir=case, email_case_label="Manual Label")
    assert get_case_label(config) == "Manual Label"
