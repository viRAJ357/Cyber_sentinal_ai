"""Local-only API for the dashboard. Binds to 127.0.0.1 by default."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timezone

from integrity import BASELINE, REPORTS, load_baseline, scan_folder


TARGET = Path(os.environ.get("CYBER_SENTINEL_TARGET", str(Path.cwd()))).expanduser().resolve()
ALLOWED_ORIGIN = os.environ.get("CYBER_SENTINEL_ALLOWED_ORIGIN", "https://viraj357.github.io")


def scan_now():
    if not TARGET.is_dir():
        raise ValueError("Configured target folder does not exist")
    files, errors = scan_folder(TARGET)
    if not BASELINE.exists():
        return {"status": "NO_BASELINE", "folder": str(TARGET), "message": "Create a trusted baseline first."}
    baseline = load_baseline(TARGET)
    old = baseline["files"]
    old_names, new_names = set(old), set(files)
    added = sorted(new_names - old_names)
    missing = sorted(old_names - new_names)
    changed = sorted(name for name in old_names & new_names if old[name] != files[name])
    status = "INCOMPLETE" if errors else ("CHANGES_DETECTED" if added or missing or changed else "CLEAN")
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "folder": str(TARGET),
        "status": status,
        "summary": {"added": len(added), "changed": len(changed), "missing": len(missing), "scan_errors": len(errors)},
        "added": added, "changed": changed, "missing": missing, "scan_errors": errors,
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    report_path = REPORTS / f"api_{stamp}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberSentinelLocalAPI/1.0"

    def send_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin")
        if origin == ALLOWED_ORIGIN:
            self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        if origin != ALLOWED_ORIGIN:
            self.send_json(403, {"error": "Origin not allowed"})
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", ALLOWED_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        self.end_headers()

    def do_GET(self):
        if urlparse(self.path).path != "/api/status":
            self.send_json(404, {"error": "Not found"})
            return
        reports = sorted(REPORTS.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True) if REPORTS.exists() else []
        if not reports:
            self.send_json(200, {"status": "NO_REPORT", "folder": str(TARGET), "message": "Run a scan to create the first report."})
            return
        try:
            report = json.loads(reports[0].read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.send_json(500, {"error": "Latest report could not be read"})
            return
        self.send_json(200, report)

    def do_POST(self):
        if urlparse(self.path).path != "/api/scan":
            self.send_json(404, {"error": "Not found"})
            return
        if self.headers.get("Origin") not in (None, ALLOWED_ORIGIN):
            self.send_json(403, {"error": "Origin not allowed"})
            return
        try:
            self.send_json(200, scan_now())
        except (OSError, ValueError) as error:
            self.send_json(500, {"error": str(error)})

    def log_message(self, format_string, *args):
        print("%s - %s" % (self.address_string(), format_string % args))


def main():
    host = os.environ.get("CYBER_SENTINEL_HOST", "127.0.0.1")
    port = int(os.environ.get("CYBER_SENTINEL_PORT", "8765"))
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("Refusing non-local bind. Keep this API on localhost unless you add authentication and TLS.")
    print(f"Cyber Sentinel local API: http://{host}:{port}")
    print(f"Target folder: {TARGET}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
