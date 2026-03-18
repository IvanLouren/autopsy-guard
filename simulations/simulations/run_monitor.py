r"""Run the AutopsyGuard monitor against a case directory.

Usage:
  python -m simulations.run_monitor <case_directory> [--install-dir <path>]

Example:
  python run_monitor.py "C:\Users\user\Cases\Forensics Image Test"
  python run_monitor.py "C:\Users\user\Cases\Forensics Image Test" --install-dir "C:\Program Files\Autopsy-4.22.1"
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from autopsyguard.config import MonitorConfig
from autopsyguard.monitor import Monitor
from autopsyguard.platform_utils import validate_case_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="AutopsyGuard Monitor")
    parser.add_argument("case_dir", type=Path, help="Path to the Autopsy case directory")
    parser.add_argument(
        "--install-dir", type=Path, default=None,
        help="Path to the Autopsy installation directory",
    )
    parser.add_argument(
        "--poll-interval", type=float, default=10.0,
        help="Seconds between detection cycles (default: 10)",
    )
    args = parser.parse_args()

    # Validate case directory
    if not validate_case_dir(args.case_dir):
        print(f"ERROR: '{args.case_dir}' does not look like a valid Autopsy case.")
        print("Expected: a directory containing a .aut file and autopsy.db")
        sys.exit(1)

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    config = MonitorConfig(
        case_dir=args.case_dir,
        autopsy_install_dir=args.install_dir,
        poll_interval=args.poll_interval,
    )

    print(f"AutopsyGuard — monitoring case: {args.case_dir}")
    print(f"Poll interval: {args.poll_interval}s")
    print("Press Ctrl+C to stop.")
    print()

    monitor = Monitor(config)
    monitor.run()


if __name__ == "__main__":
    main()
