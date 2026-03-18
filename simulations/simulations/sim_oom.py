"""Simulate a REAL OutOfMemoryError by limiting Autopsy's JVM heap.

This modifies autopsy.conf to set -Xmx64m (tiny heap), so when you open
a case and run ingest, Autopsy will genuinely run out of memory and log
a real java.lang.OutOfMemoryError.

Usage:
    1. Make sure Autopsy is CLOSED
    2. Run:  python sim_real_oom.py prepare --install-dir "C:\Program Files\Autopsy-4.22.1"
    3. Open Autopsy, open a case, start ingest → wait for OOM
    4. Run the monitor in another terminal to catch it
    5. When done: python sim_real_oom.py restore --install-dir "C:\Program Files\Autopsy-4.22.1"

What this does:
    - Backs up autopsy.conf → autopsy.conf.bak
    - Adds -J-Xmx64m to default_options (limits heap to 64 MB)
    - With only 64 MB of heap, Autopsy will crash with OutOfMemoryError
      as soon as it tries to do anything heavy (ingest, open large files)
"""

import argparse
import re
import shutil
import sys
from pathlib import Path


def find_conf(install_dir):
    """Find autopsy.conf in the install directory."""
    conf = install_dir / "etc" / "autopsy.conf"
    if not conf.is_file():
        print(f"ERROR: autopsy.conf not found at {conf}")
        sys.exit(1)
    return conf


def prepare(install_dir):
    conf = find_conf(install_dir)
    backup = conf.with_suffix(".conf.bak")

    # backup
    if backup.exists():
        print(f"Backup already exists: {backup}")
        print("Run 'restore' first if you want to start fresh.")
        sys.exit(1)

    shutil.copy2(conf, backup)
    print(f"Backed up: {conf} → {backup}")

    # read and modify
    text = conf.read_text(encoding="utf-8")

    # add -J-Xmx64m to default_options
    if "-J-Xmx" in text:
        # replace existing -Xmx
        text = re.sub(r"-J-Xmx\S+", "-J-Xmx64m", text)
        print("Replaced existing -Xmx with -Xmx64m")
    else:
        # add it after -Xms
        text = text.replace("-J-Xms24m", "-J-Xms24m -J-Xmx64m")
        print("Added -J-Xmx64m (64 MB max heap)")

    conf.write_text(text, encoding="utf-8")

    print()
    print("autopsy.conf modified. Autopsy will now run with only 64 MB heap.")
    print()
    print("Next steps:")
    print("  1. Open Autopsy")
    print("  2. Open a case and start ingest")
    print("  3. Autopsy will log: java.lang.OutOfMemoryError: Java heap space")
    print("  4. Run the monitor to detect it")
    print()
    print(f"When done, restore with:  python {sys.argv[0]} restore --install-dir \"{install_dir}\"")


def restore(install_dir):
    conf = find_conf(install_dir)
    backup = conf.with_suffix(".conf.bak")

    if not backup.exists():
        print(f"No backup found at {backup} — nothing to restore.")
        sys.exit(1)

    shutil.copy2(backup, conf)
    backup.unlink()
    print(f"Restored original autopsy.conf and deleted backup.")
    print("Autopsy will run with normal settings again.")


def main():
    parser = argparse.ArgumentParser(description="Simulate real OOM by modifying autopsy.conf")
    parser.add_argument("action", choices=["prepare", "restore"],
                        help="'prepare' = modify conf, 'restore' = undo changes")
    parser.add_argument("--install-dir", type=Path, required=True,
                        help="Autopsy installation directory")
    args = parser.parse_args()

    if args.action == "prepare":
        prepare(args.install_dir)
    else:
        restore(args.install_dir)


if __name__ == "__main__":
    main()
