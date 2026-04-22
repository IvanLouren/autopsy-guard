
"""Log file tracking utility for incremental reading and state persistence.

This module provides LogFileTracker for monitoring log files across restarts,
handling file rotation, and persisting read positions.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class LogFileTracker:
    """Tracks log file read positions with persistence support.
    
    Handles:
    - Incremental reading (only new content since last check)
    - File rotation detection (when file size decreases)
    - State persistence to JSON (survives process restarts)
    - Multiple log files with independent tracking
    
    Example:
        tracker = LogFileTracker(state_file=Path(".autopsyguard_state/log_positions.json"))
        tracker.load_positions()
        
        new_content = tracker.read_new_content(log_path)
        # ... process new_content ...
        
        tracker.save_positions()
    """
    
    def __init__(self, state_file: Path | None = None):
        """Initialize log file tracker.
        
        Args:
            state_file: Optional path to persist positions. If None, positions
                       are only kept in memory (not persisted across restarts).
        """
        self._file_offsets: dict[Path, int] = {}
        self._state_file = state_file
        
    def read_new_content(self, log_file: Path) -> str:
        """Read new content from log file since last read.
        
        Args:
            log_file: Path to log file to read
            
        Returns:
            New content as string. Empty string if no new content or file doesn't exist.
            
        Notes:
            - Automatically handles file rotation (when size < last_pos, resets to start)
            - Updates internal position tracker
            - Uses utf-8 encoding with error replacement for non-UTF8 content
        """
        if not log_file.exists() or not log_file.is_file():
            return ""
            
        try:
            file_size = log_file.stat().st_size
            last_pos = self._file_offsets.get(log_file, 0)
            
            # File was truncated/rotated - start from beginning
            if file_size < last_pos:
                logger.debug("Log file %s rotated (size decreased), resetting position", log_file)
                last_pos = 0
                
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                f.seek(last_pos)
                new_content = f.read()
                self._file_offsets[log_file] = f.tell()
                
            return new_content
            
        except OSError as e:
            logger.debug("Failed to read log file %s: %s", log_file, e)
            return ""
            
    def save_positions(self) -> None:
        """Persist current file positions to disk.
        
        Only saves if state_file was provided during initialization.
        Creates parent directories if needed.
        """
        if self._state_file is None:
            return
            
        try:
            # Convert Path keys to strings for JSON serialization
            data = {str(path): offset for path, offset in self._file_offsets.items()}
            
            # Create parent directory if needed
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            
            self._state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            logger.debug("Saved log positions to %s", self._state_file)
            
        except OSError as e:
            logger.warning("Failed to save log positions to %s: %s", self._state_file, e)
            
    def load_positions(self) -> None:
        """Load previously saved file positions from disk.
        
        Only loads if state_file exists. Silently ignores if file doesn't exist
        (normal for first run).
        """
        if self._state_file is None or not self._state_file.exists():
            return
            
        try:
            data = json.loads(self._state_file.read_text(encoding="utf-8"))
            # Convert string keys back to Path objects
            self._file_offsets = {Path(path): offset for path, offset in data.items()}
            logger.debug("Loaded %d log positions from %s", len(self._file_offsets), self._state_file)
            
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Failed to load log positions from %s: %s", self._state_file, e)
            # Continue with empty positions
            
    def reset_position(self, log_file: Path) -> None:
        """Reset position for a specific log file to start.
        
        Args:
            log_file: Path to log file to reset
        """
        self._file_offsets[log_file] = 0

    def seek_to_end(self, log_file: Path) -> None:
        """Set the tracked position for `log_file` to its current EOF.

        This is a safe helper used by detectors to ignore pre-existing
        log content (seek-to-EOF) without reading the file.
        """
        try:
            self._file_offsets[log_file] = log_file.stat().st_size
        except OSError:
            # If the file disappears between discovery and stat, skip.
            pass

    def tracked_count(self) -> int:
        """Return number of files currently tracked."""
        return len(self._file_offsets)
        
    def get_position(self, log_file: Path) -> int:
        """Get current read position for a log file.
        
        Args:
            log_file: Path to log file
            
        Returns:
            Current byte offset, or 0 if never read
        """
        return self._file_offsets.get(log_file, 0)
