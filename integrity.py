import argparse
import hashlib
import json
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

        try:
            relative = str(path.relative_to(root))
            results[relative] = sha256_file(path)
        except (OSError, ValueError) as error:
            errors.append({
                "file": str(path.relative_to(root)),
                "error": type(error).__name__
            })

    return results, errors


def save_report(report):
    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output = REPORTS / f"report_{stamp}.json"
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"JSON report saved: {output}")


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
            print("Baseline already exists.")
            print("Use check mode, or back up and remove the old baseline")
            print("manually if you intentionally want a new baseline.")
            return

        STATE.mkdir(parents=True, exist_ok=True)
        data = {
            "root": str(root),
            "created_at": now,
            "files": files
        }
        BASELINE.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

        print("Baseline created.")
        print("Files recorded:", len(files))

    else:
        if not BASELINE.exists():
            print("No baseline found. Run baseline mode first.")
            return

        data = json.loads(BASELINE.read_text(encoding="utf-8"))

        if data.get("root") != str(root):
            print("ERROR: This is a different folder than the baseline.")
            return

        old = data["files"]
        old_names, new_names = set(old), set(files)

        added = sorted(new_names - old_names)
        missing = sorted(old_names - new_names)
        changed = sorted(
            name for name in old_names & new_names
            if old[name] != files[name]
        )

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

        save_report({
            "timestamp": now,
            "folder": str(root),
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
        print("Some files could not be read:", len(errors))
        print("Review the report before relying on the results.")


if __name__ == "__main__":
    main()
