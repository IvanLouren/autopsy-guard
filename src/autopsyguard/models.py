"""Data models for AutopsyGuard crash/anomaly events."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class CrashType(enum.Enum):
    """Classification of all identified Autopsy crash/anomaly types."""

    PROCESS_DISAPPEARED = "process_disappeared"
    JVM_CRASH = "jvm_crash"
    OUT_OF_MEMORY = "out_of_memory"
    HANG = "hang"
    SOLR_CRASH = "solr_crash"
    HIGH_RESOURCE_USAGE = "high_resource_usage"
    ABNORMAL_EXIT = "abnormal_exit"
    LOG_ERROR = "log_error"
    ZOMBIE = "zombie"


class Severity(enum.Enum):
    """Severity level for detected events."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class CrashEvent:
    """Represents a single detected crash or anomaly."""

    crash_type: CrashType
    severity: Severity
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    details: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return (
            f"[{self.severity.value.upper()}] "
            f"{self.timestamp:%Y-%m-%d %H:%M:%S} - "
            f"{self.crash_type.value}: {self.message}"
        )
