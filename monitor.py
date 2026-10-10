"""Polling file-integrity monitor with explainable anomaly triage and HTTPS alerts."""
import argparse
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from anomaly_detection import score_events
from integrity import load_baseline, scan_folder


def compare_files(previous, current):
    old_names, new_names = set(previous), set(current)
    added = sorted(new_names - old_names)
    missing = sorted(old_names - new_names)
    changed = sorted(name for name in old_names & new_names if previous[name] != current[name])
    return {"added": added, "missing": missing, "changed": changed}


def send_alert(payload, webhook_url=None):
    """Send an alert only to an explicitly configured HTTPS endpoint."""
    if not webhook_url:
        print("ALERT:", json.dumps(payload, sort_keys=True))
        return True
    parsed = urlparse(webhook_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        print("Alert delivery refused: webhook must be an HTTPS URL without embedded credentials.")
        return False
    request = Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "CyberSentinelAI/1.0"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            success = 200 <= response.status < 300
            if not success:
                print("Alert delivery failed: HTTP", response.status)
            return success
    except HTTPError as error:
        print("Alert delivery failed: HTTP", error.code)
        return False
    except (URLError, TimeoutError, OSError, ValueError) as error:
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
        anomaly = score_events(root, expected, current, diff)
        signature = hashlib.sha256(json.dumps(
            {"status": status, "diff": diff, "errors": errors, "anomaly": anomaly},
            sort_keys=True,
        ).encode()).hexdigest()
        if status != "CLEAN" and signature != last_signature:
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "folder": str(root),
                "status": status,
                "changes": diff,
                "anomaly_detection": anomaly,
                "scan_errors": errors,
            }
            send_alert(payload, webhook_url)
        print(
            datetime.now(timezone.utc).isoformat(), status,
            "added=", len(diff["added"]), "changed=", len(diff["changed"]),
            "missing=", len(diff["missing"]), "errors=", len(errors),
            "anomalies=", anomaly["anomaly_count"], "engine=", anomaly["engine"],
        )
        last_signature = signature
        if once:
            return 2 if errors else (1 if any(diff.values()) else 0)
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor file integrity against a trusted baseline and triage unusual paths."
    )
    parser.add_argument("folder", help="Folder you own and are authorized to monitor")
    parser.add_argument("--interval", type=int, default=10, help="Polling interval in seconds (minimum 2)")
    parser.add_argument("--once", action="store_true", help="Run one check and exit")
    parser.add_argument(
        "--webhook", default=os.environ.get("CYBER_SENTINEL_WEBHOOK_URL"),
        help="Optional HTTPS webhook URL; may also use CYBER_SENTINEL_WEBHOOK_URL",
    )
    args = parser.parse_args()
    if args.interval < 2:
        parser.error("--interval must be at least 2 seconds")
    try:
        result = run_monitor(args.folder, args.interval, args.once, args.webhook)
        if args.once:
            raise SystemExit(result)
    except (ValueError, OSError) as error:
        parser.exit(2, f"ERROR: {type(error).__name__}: {error}\n")


if __name__ == "__main__":
    main()
