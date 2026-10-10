"""Polling-based file integrity monitor with optional webhook alerts."""
import argparse
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import Request, urlopen
from pathlib import Path

from integrity import BASELINE, load_baseline, scan_folder, STATE


def compare_files(previous, current):
    old_names, new_names = set(previous), set(current)
    added = sorted(new_names - old_names)
    missing = sorted(old_names - new_names)
    changed = sorted(name for name in old_names & new_names if previous[name] != current[name])
    return {"added": added, "missing": missing, "changed": changed}


def send_alert(payload, webhook_url=None):
    """Send JSON to an explicitly configured webhook, or print the alert."""
    if not webhook_url:
        print("ALERT:", json.dumps(payload, sort_keys=True))
        return True
    request = Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            return 200 <= response.status < 300
    except (URLError, TimeoutError, OSError) as error:
        print("Alert delivery failed:", type(error).__name__)
        return False


def run_monitor(folder, interval=10, once=False, webhook_url=None):
    root = Path(folder).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("Target folder does not exist")
    baseline = load_baseline(root)
    expected = baseline["files"]
    last_signature = None

    while True:
        current, errors = scan_folder(root)
        diff = compare_files(expected, current)
        status = "INCOMPLETE" if errors else (
            "CHANGES_DETECTED" if any(diff.values()) else "CLEAN"
        )
        signature = hashlib.sha256(json.dumps(
            {"status": status, "diff": diff, "errors": errors}, sort_keys=True
        ).encode()).hexdigest()
        if status != "CLEAN" and signature != last_signature:
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "folder": str(root),
                "status": status,
                "changes": diff,
                "scan_errors": errors,
            }
            send_alert(payload, webhook_url)
        print(datetime.now(timezone.utc).isoformat(), status,
              "added=", len(diff["added"]), "changed=", len(diff["changed"]),
              "missing=", len(diff["missing"]), "errors=", len(errors))
        last_signature = signature
        if once:
            return 2 if errors else (1 if any(diff.values()) else 0)
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Monitor file integrity against a trusted baseline.")
    parser.add_argument("folder", help="Folder you own and are authorized to monitor")
    parser.add_argument("--interval", type=int, default=10, help="Polling interval in seconds (minimum 2)")
    parser.add_argument("--once", action="store_true", help="Run one check and exit")
    parser.add_argument("--webhook", default=os.environ.get("CYBER_SENTINEL_WEBHOOK_URL"),
                        help="Optional HTTPS webhook URL; may also use CYBER_SENTINEL_WEBHOOK_URL")
    args = parser.parse_args()
    if args.interval < 2:
        parser.error("--interval must be at least 2 seconds")
    try:
        result = run_monitor(args.folder, args.interval, args.once, args.webhook)
        if args.once:
            raise SystemExit(result)
    except (ValueError, OSError) as error:
        parser.exit(2, f"ERROR: {error}\n")


if __name__ == "__main__":
    main()
