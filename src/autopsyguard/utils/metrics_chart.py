"""Render a memory chart for email reports."""

from __future__ import annotations

import io
import math
from typing import Any


def render_memory_chart_png(samples: list[dict[str, Any]]) -> bytes:
    """Render a memory chart as PNG bytes.

    Expects samples sorted by timestamp in ascending order.
    Returns empty bytes when there is not enough data.
    """
    if len(samples) < 2:
        return b""

    times = [sample.get("ts", 0.0) for sample in samples]
    t0 = times[0]
    x_minutes = [(ts - t0) / 60.0 for ts in times]
    memory_percent = [sample.get("memory_percent", 0.0) for sample in samples]

    rss_values = [sample.get("autopsy_rss_bytes") for sample in samples]
    has_rss = any(value is not None for value in rss_values)
    rss_gb = [
        (value / (1024 ** 3)) if value is not None else math.nan
        for value in rss_values
    ]

    import matplotlib

    matplotlib.use("Agg")
    from matplotlib import pyplot as plt

    fig, ax1 = plt.subplots(figsize=(6.2, 2.8), dpi=120)
    ax1.plot(
        x_minutes,
        memory_percent,
        color="#2563eb",
        linewidth=1.6,
        label="System memory (%)",
    )
    ax1.set_xlabel("Minutes since last email")
    ax1.set_ylabel("Memory (%)")
    ax1.set_ylim(0, 100)
    ax1.grid(True, alpha=0.2)

    lines = ax1.get_lines()
    labels = [line.get_label() for line in lines]

    if has_rss:
        ax2 = ax1.twinx()
        ax2.plot(
            x_minutes,
            rss_gb,
            color="#d97706",
            linewidth=1.4,
            label="Autopsy RSS (GB)",
        )
        ax2.set_ylabel("Autopsy RSS (GB)")
        lines += ax2.get_lines()
        labels += [line.get_label() for line in ax2.get_lines()]

    ax1.legend(lines, labels, loc="upper right", fontsize=8)

    fig.tight_layout()
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png")
    plt.close(fig)

    return buffer.getvalue()
