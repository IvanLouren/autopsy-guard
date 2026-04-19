import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

def setup_logging(log_dir: Path | None = None, level: int = logging.INFO) -> None:
    """Configure centralized logging for AutopsyGuard."""
    
    # Concise format for console (no module path clutter)
    console_format = logging.Formatter(
        "%(asctime)s │ %(levelname)-7s │ %(message)s",
        datefmt="%H:%M:%S"
    )
    
    # Detailed format for file (includes module for debugging)
    file_format = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # 1. Console Handler (Prints to terminal)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_format)

    # Get the root logger and set the level
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear any existing handlers so we don't double-print
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)

    # 2. File Handler (Optional: saves to a file so we have a history)
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "autopsyguard.log"
        
        # We use RotatingFileHandler so the log file is capped at 5MB limit.
        file_handler = RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(file_format)
        root_logger.addHandler(file_handler)

    # Matplotlib's font manager can be very noisy at DEBUG level (it scans system
    # fonts and logs scores). Bump its log level to WARNING so our app's DEBUG
    # output stays useful without flooding the console with font entries.
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
    logging.getLogger("matplotlib.font_manager").setLevel(logging.WARNING)
