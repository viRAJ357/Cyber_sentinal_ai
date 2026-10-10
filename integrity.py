import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

STATE = Path.home() / ".cyber-sentinel-ai"
BASELINE = STATE / "integrity_baseline.json"
REPORTS = STATE / "reports"


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_folder(root):
    results = {}
    errors = []
    excluded_dirs = {".git", "__pycache__"}
    excluded_suffixes = {".pyc"}

    for path in sorted(root.rglob("*")):
        relative_path = path.relative_to(root)

        if any(part in excluded_dirs for part in relative_path.parts):
            continue
        if path.suffix in excluded_suffixes:
            continue
        if path.is_symlink() or not path.is_file():
            continue

        relative = str(relative_path)
        try:
            results[relative] = sha256_file(path)
        except OSError as error:
            errors.append({
                "file": relative,
                "error": type(error).__name__
            })

    return results, errors


def save_report(report):
    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    output = REPORTS / f"report_{stamp}.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("JSON report saved:", output)


def _baseline_signature(data, key):
    """HMAC-sign canonical baseline JSON, excluding the signature field."""
    unsigned = {name: value for name, value in data.items() if name != "hmac_sha256"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def load_baseline(root):
    try:
        data = json.loads(BASELINE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(
            f"Baseline cannot be read: {type(error).__name__}"
        ) from error

    if not isinstance(data, dict):
        raise ValueError("Baseline must be a JSON object")

    if data.get("root") != str(root):
        raise ValueError("Baseline belongs to a different folder")

    files = data.get("files")
    if not isinstance(files, dict):
        raise ValueError("Baseline 'files' must be a JSON object")

    for name, digest in files.items():
        if not isinstance(name, str) or not isinstance(digest, str):
            raise ValueError("Baseline contains invalid file entries")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Baseline contains an invalid SHA-256 hash")

    key = os.environ.get("CYBER_SENTINEL_BASELINE_KEY")
    signature = data.get("hmac_sha256")
    if key and not signature:
        raise ValueError("A signing key is configured but the baseline is unsigned")
    if signature and not key:
        raise ValueError("Signed baseline requires CYBER_SENTINEL_BASELINE_KEY")
    if signature:
        if not isinstance(signature, str) or not hmac.compare_digest(
            signature, _baseline_signature(data, key)
        ):
            raise ValueError("Baseline signature verification failed")

    return data


def main():
    parser = argparse.ArgumentParser(
        description="Cyber Sentinel AI - File Integrity Audit"
    )
    parser.add_argument(
        "mode", choices=["baseline", "check"],
        help="Create a baseline or compare against it"
    )
    parser.add_argument(
        "folder", help="Folder you own and are authorized to audit"
    )
    args = parser.parse_args()

    root = Path(args.folder).expanduser().resolve()
    if not root.is_dir():
        parser.error("Folder does not exist")

    print("CYBER SENTINEL AI - FILE INTEGRITY")
    print("Target:", root)
    print("Mode:", args.mode)

    files, errors = scan_folder(root)
    now = datetime.now(timezone.utc).isoformat()

    if args.mode == "baseline":
        if BASELINE.exists():
            print("ERROR: Baseline already exists; it was not overwritten.")
            print("Back it up and review it before intentionally resetting.")
            return 2

        if errors:
            print("ERROR: Some files could not be read; baseline not created.")
            for item in errors:
                print("[READ ERROR]", item["file"], item["error"])
            return 2

        STATE.mkdir(parents=True, exist_ok=True)
        data = {"root": str(root), "created_at": now, "files": files}
        key = os.environ.get("CYBER_SENTINEL_BASELINE_KEY")
        if key:
            data["hmac_sha256"] = _baseline_signature(data, key)
        temp = BASELINE.with_suffix(".tmp")
        temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temp.replace(BASELINE)

        print("Baseline created.")
        print("Files recorded:", len(files))
        return 0

    if not BASELINE.exists():
        print("ERROR: No baseline found. Run baseline mode first.")
        return 2

    try:
        data = load_baseline(root)
    except ValueError as error:
        print("ERROR:", error)
        return 2

    old = data["files"]
    old_names, new_names = set(old), set(files)
    added = sorted(new_names - old_names)
    missing = sorted(old_names - new_names)
    changed = sorted(
        name for name in old_names & new_names
        if old[name] != files[name]
    )

    if errors:
        status = "INCOMPLETE"
    elif added or missing or changed:
        status = "CHANGES_DETECTED"
    else:
        status = "CLEAN"

    print("Status:", status)
    print("Unchanged:", len(old_names & new_names) - len(changed))
    print("Added:", len(added))
    print("Changed:", len(changed))
    print("Missing:", len(missing))

    for label, names in (
        ("ADDED", added),
        ("CHANGED", changed),
        ("MISSING", missing)
    ):
        for name in names:
            print(f"[{label}] {name}")

    for item in errors:
        print("[READ ERROR]", item["file"], item["error"])

    save_report({
        "timestamp": now,
        "folder": str(root),
        "status": status,
        "summary": {
            "added": len(added),
            "changed": len(changed),
            "missing": len(missing),
            "scan_errors": len(errors)
        },
        "added": added,
        "changed": changed,
        "missing": missing,
        "scan_errors": errors
    })

    if errors:
        return 2
    if added or missing or changed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
