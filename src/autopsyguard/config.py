"""Configuration for AutopsyGuard monitoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
import os
import logging

import yaml
from dotenv import load_dotenv

from autopsyguard.platform_utils import (
    get_autopsy_log_dir,
    get_autopsy_user_dir,
)

logger = logging.getLogger(__name__)


def _logical_cpu_count() -> int:
    try:
        count = int(os.cpu_count() or 1)
    except Exception:
        return 1
    return max(1, count)


def _autoscaled_cpu_warning_percent(logical_cores: int | None = None) -> float:
    cores = logical_cores if logical_cores is not None else _logical_cpu_count()
    return float(cores * 100.0 * 0.8)


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
    hang_confirmation_duration: float = 90.0  # 1.5 minutes
    
    # Solr health check settings for hang detection
    solr_ping_timeout: float = 5.0  # timeout for ping requests
    solr_ping_slow_threshold: float = 3.0  # slow response threshold
    solr_ping_slow_duration: float = 60.0  # duration before declaring slow
    solr_unresponsive_duration: float = 30.0  # duration before declaring unresponsive

    # Seconds without log file modification before suspecting a hang
    log_stale_timeout: float = 900.0  # 15 minutes

    # --- Resource thresholds ---
    cpu_warning_percent: float | None = None
    # Per-core CPU percent threshold (e.g., 90.0 means a single core at 90% will trigger)
    cpu_per_core_warning_percent: float = 90.0
    cpu_warning_duration: float = 600.0  # sustained for 10 min
    memory_warning_percent: float = 92.0  # of system RAM
    disk_min_free_gb: float = 2.0

    # --- Solr detector thresholds/settings ---
    solr_port: int = 23232
    solr_timeout_seconds: float = 5.0
    solr_slow_threshold_seconds: float = 4.0
    solr_slow_count_threshold: int = 4
    solr_heap_usage_warning: float = 85.0
    solr_heap_usage_critical: float = 95.0
    solr_cpu_warning: float = 90.0

    # --- Email / Notifications ---
    smtp_host: str = ""
    smtp_port: int = 587
    # Use implicit SSL (SMTP over SSL, typically port 465) instead of STARTTLS
    smtp_use_ssl: bool = False
    smtp_async: bool = False
    smtp_user: str = ""
    smtp_password: str = ""
    email_sender: str = "autopsyguard@example.com"
    email_recipient: str = ""
    # Optional human-readable label to show in emails instead of the case directory name
    email_case_label: str = ""
    # Case label policy when email_case_label is empty: real | hash
    case_name_source: str = "real"

    # --- WhatsApp Notifications (via CallMeBot) ---
    whatsapp_enabled: bool = False
    # Recipient phone number with country code, e.g. "+351912345678"
    whatsapp_phone: str = ""
    # CallMeBot API key (get it by messaging the bot on WhatsApp)
    whatsapp_apikey: str = ""

    # --- Telegram Notifications (via CallMeBot) ---
    telegram_enabled: bool = False
    # Recipient username (e.g. "@myusername") or phone number
    telegram_user: str = ""

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
    _cpu_warning_percent_user_set: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.cpu_warning_percent is None:
            self.cpu_warning_percent = _autoscaled_cpu_warning_percent()

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
        env_file: Path | None = None,
        overrides: Mapping[str, Any] | None = None,
    ) -> "MonitorConfig":
        """Build config from optional .env, YAML, and explicit overrides.

        Precedence (highest wins):
          1) Dataclass defaults
          2) YAML values
          3) Environment variables (loaded from .env file, then the real env)
          4) Explicit overrides (typically CLI args)

        The .env file is resolved in this order:
          - The path supplied via *env_file* (e.g. from ``--env-file`` CLI flag)
          - A file named ``.env`` in the current working directory
          - No file (silently skipped — existing env vars still apply)
        """
        # --- Load .env file (does not overwrite already-set env vars) ---
        _resolved_env_file: Path | None = None
        if env_file is not None:
            _resolved_env_file = env_file.resolve()
        else:
            candidate = Path.cwd() / ".env"
            if candidate.is_file():
                _resolved_env_file = candidate

        if _resolved_env_file is not None:
            load_dotenv(_resolved_env_file, override=False)

        values: dict[str, Any] = {}
        if yaml_path is not None:
            values.update(_load_yaml_config(yaml_path))
        user_set_cpu_warning = "cpu_warning_percent" in values

        # Apply environment-based overrides for secrets and sensitive fields
        values = _apply_env_overrides(values)

        if overrides:
            values.update({k: v for k, v in overrides.items() if v is not None})
            if "cpu_warning_percent" in overrides and overrides.get("cpu_warning_percent") is not None:
                user_set_cpu_warning = True

        if "case_dir" not in values:
            raise ValueError(
                "Missing required setting 'case_dir'. "
                "Provide it in config YAML or as a CLI argument."
            )

        for key in _PATH_KEYS:
            if key not in values:
                continue
            raw_path = values.get(key)
            if raw_path is None:
                continue
            if isinstance(raw_path, str) and raw_path.strip() == "":
                values[key] = None
                continue
            if not isinstance(raw_path, Path):
                values[key] = Path(raw_path)

        if "error_patterns" in values:
            patterns = values["error_patterns"]
            if not isinstance(patterns, list) or not all(
                isinstance(item, str) for item in patterns
            ):
                raise ValueError("'error_patterns' must be a list of strings")

        config = cls(**values)
        config._cpu_warning_percent_user_set = user_set_cpu_warning

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
    "smtp_async",
    "smtp_user",
    "smtp_password",
    "email_sender",
    "email_recipient",
    "email_case_label",
    "case_name_source",
    "report_interval_hours",
    "whatsapp_enabled",
    "whatsapp_phone",
    "whatsapp_apikey",
    "telegram_enabled",
    "telegram_user",
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
            if isinstance(value, str) and value.strip() == "":
                values[key] = None
                continue
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
    "whatsapp_apikey": "AUTOPSYGUARD_WHATSAPP_APIKEY",
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

    if config.cpu_warning_percent is None:
        raise ValueError("Invalid cpu_warning_percent: None")
    if config.cpu_warning_percent < 0:
        raise ValueError(f"Invalid cpu_warning_percent: {config.cpu_warning_percent} (must be >= 0)")
    logical_cores = _logical_cpu_count()
    low_cpu_floor = logical_cores * 100.0 * 0.5
    if config.cpu_warning_percent < low_cpu_floor:
        logger.warning(
            "Configured cpu_warning_percent %.1f is low for %d logical cores "
            "(recommended sustained threshold >= %.0f%%). This may cause alert noise.",
            config.cpu_warning_percent,
            logical_cores,
            _autoscaled_cpu_warning_percent(logical_cores),
        )

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
        if config.smtp_host.strip().lower() != "smtp.gmail.com":
            raise ValueError("smtp_host must be smtp.gmail.com (Google App Password mode only)")
        if not (1 <= config.smtp_port <= 65535):
            raise ValueError(f"Invalid smtp_port: {config.smtp_port} (must be 1-65535)")
        if config.smtp_port != 587:
            raise ValueError("smtp_port must be 587 for Gmail STARTTLS")
        if config.smtp_use_ssl:
            raise ValueError("smtp_use_ssl must be false for Gmail STARTTLS (port 587)")

    # Validate report interval
    if config.report_interval_hours <= 0:
        raise ValueError(f"Invalid report_interval_hours: {config.report_interval_hours} (must be > 0)")

    case_name_source = (config.case_name_source or "real").strip().lower()
    if case_name_source not in {"real", "hash"}:
        raise ValueError("case_name_source must be one of: real, hash")

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
    # Verify the path looks like an Autopsy case directory (has .aut or Log/)
    from autopsyguard.platform_utils import validate_case_dir

    if not validate_case_dir(config.case_dir):
        raise ValueError(
            f"'{config.case_dir}' does not look like a valid Autopsy case directory "
            f"(missing .aut file or Log/ directory)."
        )


def _validate_config(config: MonitorConfig) -> None:  # pragma: no cover - kept for compatibility
    """Backward-compatible wrapper (validates everything)."""
    _validate_config_types(config)
    _validate_config_filesystem(config)



