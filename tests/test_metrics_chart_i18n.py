from __future__ import annotations

import time

from autopsyguard.utils.metrics_chart import render_system_chart_png


def _samples() -> list[dict[str, float]]:
    t0 = time.time()
    return [
        {"ts": t0, "cpu_percent": 10.0, "memory_percent": 20.0, "disk_read_bytes": 0, "disk_write_bytes": 0},
        {"ts": t0 + 60, "cpu_percent": 30.0, "memory_percent": 40.0, "disk_read_bytes": 1000, "disk_write_bytes": 2000},
    ]


def test_chart_renders_in_pt_and_en_with_alert_window() -> None:
    for lang in ("pt", "en"):
        png = render_system_chart_png(
            _samples(),
            alert_windows=[(1_000_000.0, 1_000_030.0)],
            language=lang,
        )
        assert png[:4] == b"\x89PNG"
