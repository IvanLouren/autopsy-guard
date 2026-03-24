"""CLI entry point for AutopsyGuard.

Usage:
    python -m autopsyguard <case_dir> [options]

Example:
    python -m autopsyguard "C:/Cases/MyCase" --poll-interval 10
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from autopsyguard.config import MonitorConfig
from autopsyguard.monitor import Monitor
from autopsyguard.platform_utils import validate_case_dir


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="autopsyguard",
        description="Monitor Autopsy forensic software for crashes and anomalies.",
    )
    
    parser.add_argument(
        "case_dir",
        type=Path,
        help="Path to the Autopsy case directory to monitor",
    )
    
    parser.add_argument(
        "--autopsy-dir",
        type=Path,
        default=None,
        help="Path to Autopsy installation directory (for JVM crash detection)",
    )
    
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=10.0,
        help="Polling interval in seconds (default: 10)",
    )
    
    parser.add_argument(
        "--hang-timeout",
        type=float,
        default=300.0,
        help="Seconds of inactivity before declaring a hang (default: 300)",
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip case directory validation (for testing)",
    )
    
    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_args()
    setup_logging(args.verbose)
    
    logger = logging.getLogger("autopsyguard")
    
    # Validate case directory
    case_dir = args.case_dir.resolve()
    if not args.skip_validation:
        if not case_dir.exists():
            logger.error("Case directory does not exist: %s", case_dir)
            return 1
        if not validate_case_dir(case_dir):
            logger.error(
                "Invalid Autopsy case directory: %s\n"
                "Expected to find a .aut file and autopsy.db",
                case_dir,
            )
            return 1
    
    # Build configuration
    config = MonitorConfig(
        case_dir=case_dir,
        autopsy_install_dir=args.autopsy_dir,
        poll_interval=args.poll_interval,
        hang_timeout=args.hang_timeout,
    )
    
    logger.info("=" * 60)
    logger.info("AutopsyGuard - Forensic Software Monitor")
    logger.info("=" * 60)
    logger.info("Case directory: %s", config.case_dir)
    logger.info("Poll interval: %.1fs", config.poll_interval)
    logger.info("Hang timeout: %.1fs", config.hang_timeout)
    logger.info("=" * 60)
    
    # Create and run monitor
    monitor = Monitor(config)
    
    try:
        monitor.run()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
