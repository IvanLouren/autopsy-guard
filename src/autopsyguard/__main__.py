"""CLI entry point for AutopsyGuard.

Usage:
    python -m autopsyguard [case_dir] [options]

Example:
    python -m autopsyguard "C:/Cases/MyCase" --poll-interval 10
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from autopsyguard.config import MonitorConfig
from autopsyguard.logger import setup_logging
from autopsyguard.monitor import Monitor
from autopsyguard.platform_utils import validate_case_dir


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="autopsyguard",
        description="Monitor Autopsy forensic software for crashes and anomalies.",
    )
    
    parser.add_argument(
        "case_dir",
        type=Path,
        nargs="?",
        default=None,
        help="Path to the Autopsy case directory to monitor",
    )

    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to YAML config file (default: ./config.yml when present)",
    )
    
    parser.add_argument(
        "--autopsy-dir",
        type=Path,
        default=argparse.SUPPRESS,
        help="Path to Autopsy installation directory (for JVM crash detection)",
    )
    
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=argparse.SUPPRESS,
        help="Polling interval in seconds (default: 10)",
    )
    
    parser.add_argument(
        "--hang-timeout",
        type=float,
        default=argparse.SUPPRESS,
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
    
    level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=level)
    
    logger = logging.getLogger("autopsyguard")
    
    # Validate case directory
    config_path = args.config
    if config_path is None:
        default_config = Path.cwd() / "config.yml"
        config_path = default_config if default_config.is_file() else None
    else:
        config_path = config_path.resolve()

    try:
        overrides = {
            "case_dir": args.case_dir.resolve() if args.case_dir is not None else None,
        }
        if hasattr(args, "autopsy_dir"):
            overrides["autopsy_install_dir"] = args.autopsy_dir.resolve()
        if hasattr(args, "poll_interval"):
            overrides["poll_interval"] = args.poll_interval
        if hasattr(args, "hang_timeout"):
            overrides["hang_timeout"] = args.hang_timeout

        config = MonitorConfig.from_sources(
            yaml_path=config_path,
            overrides=overrides,
        )
    except ValueError as exc:
        logger.error(str(exc))
        return 1

    case_dir = config.case_dir.resolve()
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
