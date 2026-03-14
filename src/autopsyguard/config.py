"""Configuration for AutopsyGuard monitoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from autopsyguard.platform_utils import (
    get_autopsy_log_dir,
    get_autopsy_user_dir,
)


@dataclass
class MonitorConfig:
    """All settings needed by the monitoring system."""

    # Required: path to the Autopsy case being monitored
    case_dir: Path

    # Optional: path to the Autopsy installation directory
    autopsy_install_dir: Path | None = None

    # Polling interval in seconds
    poll_interval: float = 10.0

    # --- Hang detection ---
    # Seconds of near-zero CPU before declaring a hang
    hang_cpu_threshold: float = 1.0  # percent
    hang_timeout: float = 300.0  # 5 minutes

    # Seconds without log file modification before suspecting a hang
    log_stale_timeout: float = 600.0  # 10 minutes

    # --- Resource thresholds ---
    cpu_warning_percent: float = 95.0
    cpu_warning_duration: float = 300.0  # sustained for 5 min
    memory_warning_percent: float = 90.0  # of system RAM
    disk_min_free_gb: float = 1.0

    # --- Log error patterns ---
    error_patterns: list[str] = field(default_factory=lambda: [
        "java.lang.OutOfMemoryError",
        "SEVERE",
        "Exception",
        "FATAL",
        "StackOverflowError",
    ])

    @property
    def user_dir(self) -> Path:
        return get_autopsy_user_dir()

    @property
    def global_log_dir(self) -> Path:
        return get_autopsy_log_dir()
