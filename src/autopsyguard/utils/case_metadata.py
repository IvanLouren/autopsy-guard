"""Read case display metadata from Autopsy ``*.aut`` descriptor files."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path


def _element_local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _child_text(parent: ET.Element, local_name: str) -> str | None:
    for child in parent:
        if _element_local_name(child.tag) == local_name:
            text = (child.text or "").strip()
            if text:
                return text
    return None


def read_autopsy_case_display_name(case_dir: Path) -> str | None:
    """Return the case name shown in Autopsy (DisplayName, else Name) from ``*.aut``."""
    try:
        aut_files = sorted(case_dir.glob("*.aut"))
    except OSError:
        return None

    for path in aut_files:
        try:
            root = ET.parse(path).getroot()
        except (ET.ParseError, OSError):
            continue

        for case_el in root.iter():
            if _element_local_name(case_el.tag) != "Case":
                continue
            display = _child_text(case_el, "DisplayName")
            if display:
                return display
            name = _child_text(case_el, "Name")
            if name:
                return name

        for el in root.iter():
            if _element_local_name(el.tag) == "DisplayName":
                text = (el.text or "").strip()
                if text:
                    return text

    return None
