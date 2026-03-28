"""Configuration for AutopsyGuard monitoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

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

    # --- Solr detector thresholds/settings ---
    solr_port: int = 23232
    solr_timeout_seconds: float = 5.0
    solr_slow_threshold_seconds: float = 2.0
    solr_slow_count_threshold: int = 3
    solr_heap_usage_warning: float = 85.0
    solr_heap_usage_critical: float = 95.0
    solr_cpu_warning: float = 90.0

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

    @classmethod
    def from_sources(
        cls,
        *,
        yaml_path: Path | None = None,
        overrides: Mapping[str, Any] | None = None,
    ) -> "MonitorConfig":
        """Build config from optional YAML + explicit overrides.

        Precedence:
          1) Dataclass defaults
          2) YAML values
          3) Explicit overrides (typically CLI args)
        """
        values: dict[str, Any] = {}
        if yaml_path is not None:
            values.update(_load_yaml_config(yaml_path))

        if overrides:
            values.update({k: v for k, v in overrides.items() if v is not None})

        if "case_dir" not in values:
            raise ValueError(
                "Missing required setting 'case_dir'. "
                "Provide it in config YAML or as a CLI argument."
            )

        if not isinstance(values["case_dir"], Path):
            values["case_dir"] = Path(values["case_dir"])
        if values.get("autopsy_install_dir") is not None and not isinstance(
            values["autopsy_install_dir"], Path
        ):
            values["autopsy_install_dir"] = Path(values["autopsy_install_dir"])

        if "error_patterns" in values:
            patterns = values["error_patterns"]
            if not isinstance(patterns, list) or not all(
                isinstance(item, str) for item in patterns
            ):
                raise ValueError("'error_patterns' must be a list of strings")

        return cls(**values)


_SUPPORTED_CONFIG_KEYS = {
    "case_dir",
    "autopsy_install_dir",
    "poll_interval",
    "hang_cpu_threshold",
    "hang_timeout",
    "log_stale_timeout",
    "cpu_warning_percent",
    "cpu_warning_duration",
    "memory_warning_percent",
    "disk_min_free_gb",
    "solr_port",
    "solr_timeout_seconds",
    "solr_slow_threshold_seconds",
    "solr_slow_count_threshold",
    "solr_heap_usage_warning",
    "solr_heap_usage_critical",
    "solr_cpu_warning",
    "error_patterns",
}

_PATH_KEYS = {"case_dir", "autopsy_install_dir"}


def _load_yaml_config(path: Path) -> dict[str, Any]:
    """Load config values from YAML and validate key names/types."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Could not read config file: {path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in config file: {path}") from exc

    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"Top-level YAML content must be a mapping: {path}")

    unknown_keys = set(raw.keys()) - _SUPPORTED_CONFIG_KEYS
    if unknown_keys:
        key_list = ", ".join(sorted(unknown_keys))
        raise ValueError(f"Unknown config key(s): {key_list}")

    values: dict[str, Any] = {}
    for key, value in raw.items():
        if key in _PATH_KEYS and value is not None:
            path_value = Path(value)
            if not path_value.is_absolute():
                path_value = (path.parent / path_value).resolve()
            values[key] = path_value
        else:
            values[key] = value

    return values
