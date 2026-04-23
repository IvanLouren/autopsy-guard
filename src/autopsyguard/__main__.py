"""CLI entry point for AutopsyGuard.

Usage:
    autopsyguard [case_dir] [options]

Examples:
    autopsyguard                                  # auto-discovers config in cwd
    autopsyguard "C:/Cases/MyCase" --poll-interval 10
    autopsyguard --config config.production.yml
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from autopsyguard.config import MonitorConfig
from autopsyguard.logger import setup_logging
from autopsyguard.monitor import Monitor


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
        help="Path to YAML config file (auto-discovers config.development.yml, "
             "config.production.yml, or config.yml in cwd)",
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
        # Auto-discover config by convention: development → production → legacy
        for name in ("config.development.yml", "config.production.yml", "config.yml"):
            candidate = Path.cwd() / name
            if candidate.is_file():
                config_path = candidate
                break
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

    if not args.skip_validation:
        try:
            config.validate_filesystem()
        except ValueError as exc:
            logger.error(str(exc))
            return 1
    
    # Clean startup banner
    print("\n╔═══════════════════════════════════════════════════════════╗")
    print("║           🔍 AutopsyGuard - Forensic Monitor 🔍           ║")
    print("╚═══════════════════════════════════════════════════════════╝")
    print(f"  Case:     {config.case_dir.name}")
    print(f"  Polling:  {config.poll_interval:.0f}s │ Hang timeout: {config.hang_timeout:.0f}s")
    print(f"  Email:    {'✅ Enabled' if config.smtp_host else '❌ Disabled'}")
    print("─" * 61)
    
    # Create and run monitor
    monitor = Monitor(config)
    # Set notifier uptime start on the monitor's EmailNotifier instance
    monitor.notifier.set_start_time()
    
    try:
        monitor.run()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
