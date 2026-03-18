r"""Simulate a REAL OutOfMemoryError by limiting Autopsy's JVM heap.

This modifies BOTH system and user autopsy.conf to set -Xmx256m (limited heap),
so when you open a case and run ingest, Autopsy will genuinely run out of
memory and log a real java.lang.OutOfMemoryError.

Usage:
    1. Make sure Autopsy is CLOSED
    2. Run:  python sim_oom.py prepare --install-dir "C:\Program Files\Autopsy-4.22.1"
    3. Open Autopsy, open a case, start ingest → wait for OOM
    4. Run the monitor in another terminal to catch it
    5. When done: python sim_oom.py restore --install-dir "C:\Program Files\Autopsy-4.22.1"

What this does:
    - Backs up autopsy.conf (system AND user) → autopsy.conf.bak
    - Sets -J-Xmx64m (limits heap to 64 MB)
    - With only 64 MB of heap, Autopsy will crash with OutOfMemoryError
      as soon as it tries to do anything heavy (ingest, open large files)
"""

import argparse
import os
import re
import shutil
import sys
from pathlib import Path


def get_user_conf():
    """Get the user-level autopsy.conf path."""
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        return Path(appdata) / "autopsy" / "etc" / "autopsy.conf"
    return Path.home() / ".autopsy" / "etc" / "autopsy.conf"


def find_conf(install_dir):
    """Find autopsy.conf in the install directory."""
    conf = install_dir / "etc" / "autopsy.conf"
    if not conf.is_file():
        print(f"ERROR: autopsy.conf not found at {conf}")
        sys.exit(1)
    return conf


def modify_conf(conf):
    """Modify a single conf file with 64MB heap limit."""
    backup = conf.with_suffix(".conf.bak")

    if backup.exists():
        print(f"  Backup already exists: {backup}")
        return False

    shutil.copy2(conf, backup)
    print(f"  Backed up: {conf.name} → {backup.name}")

    text = conf.read_text(encoding="utf-8")

    # Replace or add -Xmx1536m (enough to open case, crashes during heavy ingest)
    if "-J-Xmx" in text:
        text = re.sub(r"-J-Xmx\S+", "-J-Xmx1536m", text)
    else:
        text = text.replace("-J-Xms24m", "-J-Xms24m -J-Xmx1536m")

    conf.write_text(text, encoding="utf-8")
    return True


def restore_conf(conf):
    """Restore a single conf file from backup."""
    backup = conf.with_suffix(".conf.bak")

    if not backup.exists():
        return False

    shutil.copy2(backup, conf)
    backup.unlink()
    print(f"  Restored: {conf}")
    return True


def prepare(install_dir):
    print("Modifying system autopsy.conf...")
    system_conf = find_conf(install_dir)
    if not modify_conf(system_conf):
        print("Run 'restore' first if you want to start fresh.")
        sys.exit(1)

    user_conf = get_user_conf()
    if user_conf.is_file():
        print("Modifying user autopsy.conf...")
        modify_conf(user_conf)

    print()
    print("autopsy.conf modified. Autopsy will now run with only 256 MB heap.")
    print()
    print("Next steps:")
    print("  1. Open Autopsy")
    print("  2. Open a case and start ingest")
    print("  3. Autopsy will log: java.lang.OutOfMemoryError: Java heap space")
    print("  4. Run the monitor to detect it")
    print()
    print(f"When done, restore with:  python {sys.argv[0]} restore --install-dir \"{install_dir}\"")


def restore(install_dir):
    print("Restoring configs...")
    system_conf = find_conf(install_dir)
    restored_system = restore_conf(system_conf)

    user_conf = get_user_conf()
    restored_user = False
    if user_conf.is_file():
        restored_user = restore_conf(user_conf)

    if not restored_system and not restored_user:
        print("No backups found — nothing to restore.")
        sys.exit(1)

    print("Restored original autopsy.conf(s).")
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
