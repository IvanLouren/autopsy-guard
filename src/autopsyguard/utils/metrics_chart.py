"""Render a compact system chart (CPU, memory, disk I/O) for email reports.

Provides a two-row PNG: top row shows CPU% and Memory%, bottom row shows
disk read/write rates (MB/s). Expects samples sorted by timestamp ascending.
"""

from __future__ import annotations

import io
import math
from typing import Any

import matplotlib

matplotlib.use("Agg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg


def render_system_chart_png(
    samples: list[dict[str, Any]],
    alert_windows: list[tuple[float, float]] | None = None,
) -> bytes:
    """Render a system chart as PNG bytes.

    Returns empty bytes when there is not enough data (fewer than 2 samples).
    """
    if len(samples) < 2:
        return b""

    times = [sample.get("ts", 0.0) for sample in samples]
    t0 = times[0]
    x_minutes = [(ts - t0) / 60.0 for ts in times]

    cpu = [sample.get("cpu_percent", 0.0) for sample in samples]
    memory = [sample.get("memory_percent", 0.0) for sample in samples]
    smooth_w = 5 if len(cpu) >= 5 else max(1, len(cpu))
    cpu_s = _moving_average(cpu, smooth_w)
    mem_s = _moving_average(memory, smooth_w)

    # Autopsy RSS (optional)
    rss_values = [sample.get("autopsy_rss_bytes") for sample in samples]
    has_rss = any(value is not None for value in rss_values)
    rss_gb = [(v / (1024 ** 3)) if v is not None else math.nan for v in rss_values]

    # Compute disk I/O rates (bytes/sec) from cumulative counters
    read_bytes = [sample.get("disk_read_bytes") for sample in samples]
    write_bytes = [sample.get("disk_write_bytes") for sample in samples]
    read_bps = [0.0] * len(samples)
    write_bps = [0.0] * len(samples)
    for i in range(1, len(samples)):
        dt = max(1e-6, times[i] - times[i - 1])
        try:
            read_bps[i] = ( (read_bytes[i] or 0) - (read_bytes[i - 1] or 0) ) / dt
        except Exception:
            read_bps[i] = 0.0
        try:
            write_bps[i] = ( (write_bytes[i] or 0) - (write_bytes[i - 1] or 0) ) / dt
        except Exception:
            write_bps[i] = 0.0
    # Convert to MB/s
    read_mbps = [v / (1024 ** 2) for v in read_bps]
    write_mbps = [v / (1024 ** 2) for v in write_bps]

    fig = Figure(figsize=(6.2, 4.2), dpi=120)
    ax_top, ax_bot = fig.subplots(2, 1, gridspec_kw={"height_ratios": [2, 1]})

    # If alert windows were provided (list of (start_ts, end_ts) epoch seconds),
    # convert them to minutes relative to t0 and shade those regions on the CPU plot.
    alert_drawn = False
    if alert_windows:
        # choose a gentle red/pink shade and modest opacity so the plot remains readable
        alert_color = "#fee2e2"
        alert_line_color = "#dc2626"
        alert_alpha = 0.25
        for start_ts, end_ts in alert_windows:
            start_min = (start_ts - t0) / 60.0
            end_min = (end_ts - t0) / 60.0

            if start_ts == end_ts or abs(end_min - start_min) < 1e-6:
                # Point-in-time alert (zero duration): draw a vertical line
                if x_minutes[0] <= start_min <= x_minutes[-1]:
                    ax_top.axvline(start_min, color=alert_line_color, alpha=0.5,
                                   linewidth=1.2, linestyle="--", zorder=0)
                    try:
                        ax_top.text(start_min, 95, "ALERTA", color="#7f1d1d",
                                    fontsize=8, fontweight="600", ha="center",
                                    va="top", backgroundcolor=(1, 1, 1, 0.6))
                    except Exception:
                        pass
                    alert_drawn = True
            else:
                # skip invalid windows
                if end_ts < start_ts:
                    continue
                # Only draw if overlaps the plotted range
                if end_min < x_minutes[0] or start_min > x_minutes[-1]:
                    continue
                ax_top.axvspan(start_min, end_min, color=alert_color, alpha=alert_alpha, zorder=0)
                # annotate window
                mid = max(start_min, x_minutes[0]) + (min(end_min, x_minutes[-1]) - max(start_min, x_minutes[0])) / 2
                try:
                    y = 95
                    ax_top.text(mid, y, "ALERTA", color="#7f1d1d", fontsize=8, fontweight="600",
                                ha="center", va="top", backgroundcolor=(1, 1, 1, 0.6))
                except Exception:
                    pass
                alert_drawn = True

    # Top: CPU% and Memory%
    ax_top.plot(x_minutes, cpu_s, color="#e11d48", linewidth=1.6, label="CPU (%)")
    ax_top.plot(x_minutes, mem_s, color="#2563eb", linewidth=1.6, label="Memory (%)")
    ax_top.set_ylabel("Percent (%)")
    ax_top.set_ylim(0, 100)
    ax_top.grid(True, alpha=0.15)
    lines = [l for l in ax_top.get_lines() if not l.get_label().startswith("_")]
    labels = [l.get_label() for l in lines]

    if has_rss:
        ax_rss = ax_top.twinx()
        ax_rss.plot(x_minutes, rss_gb, color="#d97706", linewidth=1.2, linestyle="--", label="Autopsy RSS (GB)")
        ax_rss.set_ylabel("RSS (GB)")
        lines += ax_rss.get_lines()
        labels += [l.get_label() for l in ax_rss.get_lines()]

    # Add alert legend entry only if any alert was actually drawn on the chart
    if alert_drawn:
        from matplotlib.lines import Line2D
        alert_legend = Line2D([0], [0], color="#dc2626", linewidth=1.2,
                              linestyle="--", alpha=0.5, label="Período de alerta")
        lines.append(alert_legend)
        labels.append(alert_legend.get_label())
    ax_top.legend(lines, labels, loc="upper right", fontsize=8)
    ax_top.set_xlabel("Minutes since last email")

    # Bottom: Disk I/O MB/s
    ax_bot.plot(x_minutes, read_mbps, color="#10b981", linewidth=1.4, label="Read (MB/s)")
    ax_bot.plot(x_minutes, write_mbps, color="#6366f1", linewidth=1.4, label="Write (MB/s)")
    ax_bot.set_ylabel("MB/s")
    ax_bot.set_xlabel("Minutes since last email")
    ax_bot.grid(True, alpha=0.15)
    ax_bot.legend(loc="upper right", fontsize=8)

    fig.tight_layout()
    buf = io.BytesIO()
    canvas = FigureCanvasAgg(fig)
    canvas.print_png(buf)
    # Clear the figure to free memory
    fig.clear()
    return buf.getvalue()


def _moving_average(values: list[float], window: int) -> list[float]:
    """Compute a simple moving average with a fixed window size."""
    if window <= 1:
        return values

    smoothed: list[float] = []
    running_sum = 0.0
    for index, value in enumerate(values):
        running_sum += value
        if index >= window:
            running_sum -= values[index - window]
            smoothed.append(running_sum / window)
        else:
            smoothed.append(running_sum / (index + 1))
    return smoothed
