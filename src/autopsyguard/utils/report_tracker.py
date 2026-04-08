"""Report deduplication tracker for preventing duplicate event notifications.

This module provides ReportTracker for managing which events have been reported,
preventing spam while allowing re-reporting after recovery.
"""

from __future__ import annotations


class ReportTracker:
    """Tracks which events have been reported to prevent duplicates.
    
    Manages boolean flags for different event types, providing a cleaner
    alternative to scattered _xyz_reported flags throughout detector code.
    
    Example:
        tracker = ReportTracker()
        
        if high_cpu and not tracker.has_reported("high_cpu"):
            send_alert()
            tracker.mark_reported("high_cpu")
            
        if cpu_normalized:
            tracker.clear("high_cpu")
    """
    
    def __init__(self):
        """Initialize an empty report tracker."""
        self._reported: set[str] = set()
        
    def has_reported(self, event_key: str) -> bool:
        """Check if an event has already been reported."""
        return event_key in self._reported
        
    def mark_reported(self, event_key: str) -> None:
        """Mark an event as having been reported."""
        self._reported.add(event_key)
        
    def clear(self, event_key: str) -> None:
        """Clear the reported status for an event."""
        self._reported.discard(event_key)
        
    def clear_all(self) -> None:
        """Clear all reported events."""
        self._reported.clear()
        
    def get_reported_events(self) -> set[str]:
        """Get the set of all currently reported events."""
        return self._reported.copy()
