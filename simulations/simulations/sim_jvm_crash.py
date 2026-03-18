"""Simulate a REAL JVM fatal crash by forcing CrashOnOutOfMemoryError.

This modifies autopsy.conf to set -Xmx64m AND -XX:+CrashOnOutOfMemoryError,
so when Autopsy runs out of memory, instead of just logging the error,
the JVM will crash hard and produce a real hs_err_pid*.log file.

Usage:
    1. Make sure Autopsy is CLOSED
    2. Run:  python sim_real_jvm_crash.py prepare --install-dir "C:\Program Files\Autopsy-4.22.1"
    3. Open Autopsy, open a case, start ingest → JVM will crash
    4. Run the monitor to detect the hs_err_pid file
    5. When done: python sim_real_jvm_crash.py restore --install-dir "C:\Program Files\Autopsy-4.22.1"

What this does:
    - Backs up autopsy.conf → autopsy.conf.jvmcrash.bak
    - Adds -J-Xmx64m and -J-XX:+CrashOnOutOfMemoryError to default_options
    - When OOM happens, the JVM aborts immediately and writes hs_err_pid<N>.log
    - The file appears in the Autopsy install dir or user home
"""

import argparse
import re
import shutil
import sys
from pathlib import Path

CRASH_FLAGS = "-J-Xmx64m -J-XX:+CrashOnOutOfMemoryError -J-XX:+ExitOnOutOfMemoryError"


def find_conf(install_dir):
    conf = install_dir / "etc" / "autopsy.conf"
    if not conf.is_file():
        print(f"ERROR: autopsy.conf not found at {conf}")
        sys.exit(1)
    return conf


def prepare(install_dir):
    conf = find_conf(install_dir)
    backup = conf.parent / "autopsy.conf.jvmcrash.bak"

    if backup.exists():
        print(f"Backup already exists: {backup}")
        print("Run 'restore' first.")
        sys.exit(1)

    shutil.copy2(conf, backup)
    print(f"Backed up: {conf} → {backup}")

    text = conf.read_text(encoding="utf-8")

    # remove any existing -Xmx
    text = re.sub(r"\s*-J-Xmx\S+", "", text)
    # remove any existing crash flags
    text = re.sub(r"\s*-J-XX:\+CrashOnOutOfMemoryError", "", text)
    text = re.sub(r"\s*-J-XX:\+ExitOnOutOfMemoryError", "", text)

    # add our flags after -Xms24m
    text = text.replace("-J-Xms24m", f"-J-Xms24m {CRASH_FLAGS}")

    conf.write_text(text, encoding="utf-8")

    print()
    print("autopsy.conf modified with crash-on-OOM flags.")
    print()
    print("What will happen:")
    print("  1. Open Autopsy and start ingest on a case")
    print("  2. With only 64 MB heap, OOM will occur quickly")
    print("  3. -XX:+CrashOnOutOfMemoryError makes the JVM abort immediately")
    print("  4. A real hs_err_pid<N>.log file will be created")
    print("  5. The monitor will detect it as a JVM_CRASH")
    print()
    print("WARNING: Autopsy will crash hard — no graceful shutdown!")
    print(f"Restore with:  python {sys.argv[0]} restore --install-dir \"{install_dir}\"")


def restore(install_dir):
    conf = find_conf(install_dir)
    backup = conf.parent / "autopsy.conf.jvmcrash.bak"

    if not backup.exists():
        print(f"No backup found at {backup}")
        sys.exit(1)

    shutil.copy2(backup, conf)
    backup.unlink()
    print("Restored original autopsy.conf.")


def main():
    parser = argparse.ArgumentParser(description="Simulate real JVM crash via autopsy.conf")
    parser.add_argument("action", choices=["prepare", "restore"])
    parser.add_argument("--install-dir", type=Path, required=True)
    args = parser.parse_args()

    if args.action == "prepare":
        prepare(args.install_dir)
    else:
        restore(args.install_dir)


if __name__ == "__main__":
    main()
