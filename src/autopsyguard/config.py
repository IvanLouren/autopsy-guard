"""Configuration for AutopsyGuard monitoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
import os

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
    # Minimum duration for correlated hang signals before reporting
    hang_confirmation_duration: float = 60.0  # 1 minute
    
    # Solr health check settings for hang detection
    solr_ping_timeout: float = 5.0  # timeout for ping requests
    solr_ping_slow_threshold: float = 3.0  # slow response threshold
    solr_ping_slow_duration: float = 60.0  # duration before declaring slow
    solr_unresponsive_duration: float = 30.0  # duration before declaring unresponsive

    # Seconds without log file modification before suspecting a hang
    log_stale_timeout: float = 600.0  # 10 minutes

    # --- Resource thresholds ---
    cpu_warning_percent: float = 95.0
    # Per-core CPU percent threshold (e.g., 90.0 means a single core at 90% will trigger)
    cpu_per_core_warning_percent: float = 90.0
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

    # --- Email / Notifications ---
    smtp_host: str = ""
    smtp_port: int = 587
    # Use implicit SSL (SMTP over SSL, typically port 465) instead of STARTTLS
    smtp_use_ssl: bool = False
    smtp_user: str = ""
    smtp_password: str = ""
    email_sender: str = "autopsyguard@example.com"
    email_recipient: str = ""

    # --- Periodic Reporting ---
    report_interval_hours: float = 12.0

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

    def __repr__(self) -> str:
        masked = "***" if self.smtp_password else ""
        return (
            f"MonitorConfig(case_dir={self.case_dir!r}, smtp_host={self.smtp_host!r}, "
            f"smtp_user={self.smtp_user!r}, smtp_password={masked!r}, "
            f"email_recipient={self.email_recipient!r})"
        )

    def validate_filesystem(self) -> None:
        """Validate filesystem-dependent config values.

        Call this at application start-up when filesystem checks should be
        enforced (for example when `--skip-validation` is not set).
        """
        _validate_config_filesystem(self)

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

            # Apply environment-based overrides for secrets and sensitive fields
            values = _apply_env_overrides(values)

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

        config = cls(**values)

        # Validate syntactic and semantic (non-filesystem) aspects of the config
        _validate_config_types(config)

        return config


_SUPPORTED_CONFIG_KEYS = {
    "case_dir",
    "autopsy_install_dir",
    "poll_interval",
    "hang_cpu_threshold",
    "hang_timeout",
    "hang_confirmation_duration",
    "solr_ping_timeout",
    "solr_ping_slow_threshold",
    "solr_ping_slow_duration",
    "solr_unresponsive_duration",
    "log_stale_timeout",
    "cpu_warning_percent",
    "cpu_per_core_warning_percent",
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
    "smtp_host",
    "smtp_port",
    "smtp_use_ssl",
    "smtp_user",
    "smtp_password",
    "email_sender",
    "email_recipient",
    "report_interval_hours",
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


_ENV_OVERRIDES = {
    "smtp_password": "AUTOPSYGUARD_SMTP_PASSWORD",
    "smtp_user": "AUTOPSYGUARD_SMTP_USER",
}


def _apply_env_overrides(values: dict[str, Any]) -> dict[str, Any]:
    """Override config values from environment variables when present.

    This keeps secrets out of disk-backed YAML files and allows secure
    injection in deployment environments.
    """
    for field, env_var in _ENV_OVERRIDES.items():
        val = os.environ.get(env_var)
        if val is not None:
            values[field] = val
    return values


def _validate_config_types(config: MonitorConfig) -> None:
    """Validate non-filesystem configuration values for consistency and correctness.

    This function checks types, ranges and inter-field logic but does NOT
    access the filesystem. Filesystem checks should be performed explicitly
    at runtime by calling `MonitorConfig.validate_filesystem()`.
    """
    # Validate Solr port
    if not (1 <= config.solr_port <= 65535):
        raise ValueError(f"Invalid solr_port: {config.solr_port} (must be 1-65535)")

    # Validate percentage thresholds
    percentage_fields = [
        ("cpu_warning_percent", config.cpu_warning_percent),
        ("cpu_per_core_warning_percent", config.cpu_per_core_warning_percent),
        ("memory_warning_percent", config.memory_warning_percent),
        ("hang_cpu_threshold", config.hang_cpu_threshold),
        ("solr_heap_usage_warning", config.solr_heap_usage_warning),
        ("solr_heap_usage_critical", config.solr_heap_usage_critical),
        ("solr_cpu_warning", config.solr_cpu_warning),
    ]

    for field_name, value in percentage_fields:
        if not (0 <= value <= 100):
            raise ValueError(f"Invalid {field_name}: {value} (must be 0-100)")

    # Validate timeout values
    timeout_fields = [
        ("poll_interval", config.poll_interval),
        ("hang_timeout", config.hang_timeout),
        ("hang_confirmation_duration", config.hang_confirmation_duration),
        ("log_stale_timeout", config.log_stale_timeout),
        ("cpu_warning_duration", config.cpu_warning_duration),
        ("solr_timeout_seconds", config.solr_timeout_seconds),
        ("solr_slow_threshold_seconds", config.solr_slow_threshold_seconds),
        ("solr_ping_timeout", config.solr_ping_timeout),
        ("solr_ping_slow_threshold", config.solr_ping_slow_threshold),
        ("solr_ping_slow_duration", config.solr_ping_slow_duration),
        ("solr_unresponsive_duration", config.solr_unresponsive_duration),
    ]

    for field_name, value in timeout_fields:
        if value <= 0:
            raise ValueError(f"Invalid {field_name}: {value} (must be > 0)")

    # Validate count thresholds
    if config.solr_slow_count_threshold <= 0:
        raise ValueError(f"Invalid solr_slow_count_threshold: {config.solr_slow_count_threshold} (must be > 0)")

    # Validate disk space
    if config.disk_min_free_gb < 0:
        raise ValueError(f"Invalid disk_min_free_gb: {config.disk_min_free_gb} (must be >= 0)")

    # Validate email settings only if email_recipient is configured
    # (email_sender has a default, so we check recipient as the trigger)
    if config.email_recipient:
        if not config.smtp_host:
            raise ValueError("smtp_host is required when email_recipient is configured")
        if not (1 <= config.smtp_port <= 65535):
            raise ValueError(f"Invalid smtp_port: {config.smtp_port} (must be 1-65535)")

    # Validate report interval
    if config.report_interval_hours <= 0:
        raise ValueError(f"Invalid report_interval_hours: {config.report_interval_hours} (must be > 0)")

    # Validate heap thresholds are logical
    if config.solr_heap_usage_warning >= config.solr_heap_usage_critical:
        raise ValueError(
            f"solr_heap_usage_warning ({config.solr_heap_usage_warning}) must be less than "
            f"solr_heap_usage_critical ({config.solr_heap_usage_critical})"
        )


def _validate_config_filesystem(config: MonitorConfig) -> None:
    """Validate filesystem-dependent configuration (case dir presence)."""
    if not config.case_dir.exists():
        raise ValueError(f"Case directory does not exist: {config.case_dir}")
    if not config.case_dir.is_dir():
        raise ValueError(f"Case directory is not a directory: {config.case_dir}")


def _validate_config(config: MonitorConfig) -> None:  # pragma: no cover - kept for compatibility
    """Backward-compatible wrapper (validates everything)."""
    _validate_config_types(config)
    _validate_config_filesystem(config)



