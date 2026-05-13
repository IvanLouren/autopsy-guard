"""Shared base class for all AutopsyGuard notification channels."""

from __future__ import annotations

import abc
from datetime import datetime, timedelta
from typing import Any

from autopsyguard.models import CrashEvent


class BaseNotifier(abc.ABC):
    """Abstract base for every notification channel.

    Enforces a uniform public API across Email, WhatsApp, and Telegram so the
    monitor loop can treat all channels identically.

    Concrete sub-classes must implement ``send_alert``, ``send_report``, and
    ``send_ingest_report``.  The uptime helpers are provided here so they are
    not duplicated across every channel.
    """

    def __init__(self) -> None:
        self._start_time: datetime | None = None

    # ------------------------------------------------------------------
    # Uptime tracking (shared across all channels)
    # ------------------------------------------------------------------

    def set_start_time(self) -> None:
        """Record the moment this notifier became active."""
        self._start_time = datetime.now()

    def get_uptime(self) -> str:
        """Return a human-readable uptime string, e.g. ``2h 15m 30s``."""
        if self._start_time is None:
            return "N/A"
        delta = datetime.now() - self._start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        if minutes > 0:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"

    # ------------------------------------------------------------------
    # Abstract public API
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def is_enabled(self) -> bool:
        """Return True when this channel has enough config to send messages."""

    @abc.abstractmethod
    def send_alert(self, events: list[CrashEvent]) -> bool:
        """Dispatch an immediate alert for the given events.

        Returns True if the send was initiated successfully.
        """

    @abc.abstractmethod
    def send_report(
        self,
        system_status: str,
        events_last_period: int,
        metrics_samples: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Send a periodic heartbeat / status report."""

    @abc.abstractmethod
    def send_ingest_report(self, duration_seconds: float) -> bool:
        """Send a notification that an Autopsy ingest job has completed."""
