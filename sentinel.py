
#!/usr/bin/env python3

import os
import sys
import platform
from pathlib import Path
from datetime import datetime

HOME = Path.home()
ISSUES = []
CHECKS = 0

def report(title, status, details):
    global CHECKS
    CHECKS += 1
    print(f"[{status}] {title}: {details}")
    if status == "WARN":
        ISSUES.append(title)

def main():
    print("=" * 48)
    print("       CYBER SENTINEL AI")
    print("       Local Security Audit")
    print("=" * 48)
    print("Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("System:", platform.system(), platform.release())
    print("Python:", sys.version.split()[0])
    print("Home:", HOME)
    print("-" * 48)

    # Check Termux environment
    if "com.termux" in os.environ.get("PREFIX", ""):
        report("Termux environment", "PASS", "Termux detected")
    else:
        report("Termux environment", "INFO", "Termux not confirmed")

    # Check SSH directory permissions
    ssh_dir = HOME / ".ssh"

    if ssh_dir.exists():
        mode = ssh_dir.stat().st_mode & 0o777
        if mode & 0o077:
            report(
                "SSH directory permissions",
                "WARN",
                f"Permissions are {oct(mode)}; review access"
            )
        else:
            report(
                "SSH directory permissions",
                "PASS",
                f"Permissions are {oct(mode)}"
            )

        auth_keys = ssh_dir / "authorized_keys"
        if auth_keys.exists():
            key_mode = auth_keys.stat().st_mode & 0o777
            if key_mode & 0o022:
                report(
                    "SSH authorized_keys permissions",
                    "WARN",
                    f"Permissions are {oct(key_mode)}"
                )
            else:
                report(
                    "SSH authorized_keys permissions",
                    "PASS",
                    f"Permissions are {oct(key_mode)}"
                )
    else:
        report("SSH directory", "PASS", "No SSH directory found")

    # Look for filenames that deserve a privacy review.
    # File contents are never opened or printed.
    sensitive_terms = (
        "password", "passwd", "secret", "token",
        "credential", "victim", "capture", "phish"
    )

    found = []
    try:
        for item in HOME.iterdir():
            if item.name.startswith(".cache"):
                continue
            if any(term in item.name.lower() for term in sensitive_terms):
                found.append(item.name)
    except OSError:
        report("Home directory review", "WARN", "Cannot list home directory")

    if found:
        report(
            "Potentially sensitive filenames",
            "WARN",
            f"{len(found)} item(s) need a privacy review"
        )
        for name in found[:10]:
            print("    Review filename:", name)
        if len(found) > 10:
            print("    Additional filenames omitted")
    else:
        report(
            "Potentially sensitive filenames",
            "PASS",
            "No matching names found in home directory"
        )

    # Check available storage
    try:
        usage = os.statvfs(HOME)
        total = usage.f_blocks * usage.f_frsize
        free = usage.f_bavail * usage.f_frsize
        if total:
            percent = (free / total) * 100
            report(
                "Available storage",
                "PASS" if percent >= 10 else "WARN",
                f"{percent:.1f}% available"
            )
    except (OSError, AttributeError):
        report("Available storage", "INFO", "Could not determine")

    print("-" * 48)
    print("Checks completed:", CHECKS)
    print("Items requiring review:", len(ISSUES))
    print("Audit finished. No files were changed.")
    print("=" * 48)

if __name__ == "__main__":
    main()
