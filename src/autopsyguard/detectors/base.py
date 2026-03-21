"""Abstract base class for all crash/anomaly detectors."""

from __future__ import annotations

import abc

from autopsyguard.config import MonitorConfig
from autopsyguard.models import CrashEvent


class BaseDetector(abc.ABC):
    """Base class that every detector must implement.

    Each detector is responsible for one category of crash/anomaly.
    The monitor calls ``check()`` on every polling cycle.
    """

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config

    @abc.abstractmethod
    def check(self) -> list[CrashEvent]:
        """Run one detection cycle.

        Returns a list of newly detected events (empty if nothing found).
        """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable name for this detector."""
