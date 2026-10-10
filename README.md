# Cyber Sentinel AI

A defensive cybersecurity learning project for Termux and Python. Cyber Sentinel AI records a trusted SHA-256 file inventory, detects added/changed/missing files, writes JSON reports, and exposes an optional localhost API for a dashboard.

> **Project status:** Educational prototype. It is not an antivirus, EDR, or a guarantee that a device is secure. A file change or anomaly score is a reason to investigate—not proof of malware.

## Highlights

- **File integrity monitoring:** SHA-256 baseline and comparison for added, changed, and missing files.
- **Baseline authenticity:** Optional HMAC-SHA256 signatures to detect unauthorized baseline edits.
- **JSON reports:** Saved under `~/.cyber-sentinel-ai/reports/`.
- **Anomaly triage:** Optional scikit-learn Isolation Forest when enough unaffected reference files and changed-file events are available; transparent heuristic fallback otherwise.
- **Local dashboard API:** `GET /api/status` for the latest report and `POST /api/scan` for a new scan.
- **Monitoring and alerts:** Polling mode with optional HTTPS-only webhook notifications.
- **Tests and CI:** Unit tests cover integrity comparisons, signed-baseline validation, API scan behavior, anomaly triage, and webhook URL safeguards.

## Architecture

```text
Trusted folder
    |
    v
integrity.py ---- SHA-256 comparison ----> JSON report
    |                                      |
    |                                      v
    +------------------------------> anomaly_detection.py
                                           |
monitor.py <--- polling / alerts            v
                                      dashboard_api.py
                                           |
                                           v
                                      docs/index.html
```

The dashboard is a static frontend. It cannot reach a Termux API on a phone from the public internet. The development API deliberately binds to localhost.

## Quick start (Termux)

Clone the repository if you have not already done so:

```sh
git clone https://github.com/viRAJ357/Cyber_sentinal_ai.git
cd Cyber_sentinal_ai
```

Run the checks:

```sh
python -m unittest discover -s tests -v
python -m py_compile integrity.py sentinel.py anomaly_detection.py monitor.py dashboard_api.py
```

Run the basic security audit:

```sh
python sentinel.py
```

### Create and check an integrity baseline

**Only create a baseline after you have inspected the folder and trust its current contents.** If a baseline already exists, do not overwrite or remove it just to make a check pass.

```sh
python integrity.py baseline "$HOME/cyber-sentinel-ai"
python integrity.py check "$HOME/cyber-sentinel-ai"
```

Exit codes: `0` = clean, `1` = changes detected, `2` = operational error or incomplete scan.

## Optional HMAC-signed baseline

A signed baseline helps detect unauthorized changes to the baseline file. Generate the key once, protect it, and keep it separate from the repository and baseline:

```sh
mkdir -p "$HOME/.cyber-sentinel-ai"
chmod 700 "$HOME/.cyber-sentinel-ai"
python -c 'import secrets; print(secrets.token_hex(32))' > "$HOME/.cyber-sentinel-ai/baseline_key.txt"
chmod 600 "$HOME/.cyber-sentinel-ai/baseline_key.txt"
export CYBER_SENTINEL_BASELINE_KEY="$(cat "$HOME/.cyber-sentinel-ai/baseline_key.txt")"
```

Load the same environment variable in every shell that runs integrity checks, the monitor, or the API. If signing is enabled for an existing unsigned baseline, back it up and deliberately create a signed baseline from a verified clean state. Never paste the secret key into GitHub, screenshots, chat, or logs.

A key stored on the same device is not protection against an attacker who can access that account. For stronger protection, store an encrypted/off-device backup and restrict file permissions.

## Monitoring

Check once:

```sh
python monitor.py "$HOME/cyber-sentinel-ai" --once
```

Poll every 10 seconds:

```sh
python monitor.py "$HOME/cyber-sentinel-ai" --interval 10
```

The monitor does not automatically update the baseline. Investigate reported changes before deciding whether they are expected.

Optional webhook notifications require an HTTPS endpoint you control:

```sh
export CYBER_SENTINEL_WEBHOOK_URL="https://your-approved-webhook.example/endpoint"
python monitor.py "$HOME/cyber-sentinel-ai" --interval 10
```

Keep webhook URLs private and never use an endpoint you do not control.

## Anomaly detection: ML and fallback

The anomaly module extracts file/path metadata features and uses scikit-learn's Isolation Forest when the optional dependency is available, there are enough unaffected reference files, and there are events to score. The current minimum reference inventory is eight files. A clean scan with no changes has no events to score, so the report can show `heuristic_fallback` even if scikit-learn is installed.

Install the optional ML dependencies in an isolated environment where supported:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-ml.txt
```

On Termux/Android, scikit-learn may not have compatible wheels for every Python version. If installation fails, use the fallback or run the optional model on a supported desktop/Linux environment. The model is a triage aid, not a trained malware classifier; scores can produce false positives and must be reviewed.

### Synthetic ML smoke test

A synthetic smoke test was run in Google Colab and reported:

- Engine: `isolation_forest`
- Reference files: `12`
- Test input: synthetic file inventory and one synthetic added-file event

This confirms that the optional Isolation Forest code path executed for that test environment. It does **not** establish real-world malware-detection accuracy, recall, precision, or a production-ready model. Termux may use the heuristic fallback if scikit-learn is unavailable.

## Local dashboard API

In the project folder, set the target and start the API:

```sh
cd "$HOME/cyber-sentinel-ai"
export CYBER_SENTINEL_BASELINE_KEY="$(cat "$HOME/.cyber-sentinel-ai/baseline_key.txt")"
CYBER_SENTINEL_TARGET="$HOME/cyber-sentinel-ai" python dashboard_api.py
```

Default local URL: `http://127.0.0.1:8765`. If that port is already occupied, use another local port:

```sh
CYBER_SENTINEL_PORT=8766 python dashboard_api.py
```

In a second Termux session, test the endpoints:

```sh
curl -i http://127.0.0.1:8766/api/status
curl -i -X POST http://127.0.0.1:8766/api/scan
```

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/status` | Return the latest saved report |
| POST | `/api/scan` | Run an integrity scan and save a report |

**Security:** This development API is intended for localhost only. It does not provide user authentication, rate limiting, or TLS. Do not bind it to a public interface or expose it through a tunnel. CORS restrictions are not authentication.

### Dashboard website

Static dashboard source: [`docs/index.html`](docs/index.html). The GitHub Pages site is a static frontend and cannot directly access a private Termux server. Live remote use would require a separately deployed HTTPS backend with authentication, authorization, rate limiting, careful CORS configuration, and a review of which file/report data it may expose. Until then, use the API locally.

## Validation performed

Latest local verification reported by the project maintainer:

- Unit tests: **15 passed**
- Python compile check: passed
- `git diff --check`: passed
- Local `POST /api/scan`: **HTTP 200**, status `CLEAN`, zero scan errors

These are test results for the current development environment, not a security certification or proof that the software detects all attacks.

## Repository layout

```text
.
├── anomaly_detection.py
├── dashboard_api.py
├── integrity.py
├── monitor.py
├── sentinel.py
├── docs/
│   └── index.html
└── tests/
```

## Responsible use

- Scan only files and systems you own or are explicitly authorized to audit.
- Create baselines only from known-good states.
- Keep signing keys and webhook URLs out of version control.
- Review changes and anomaly findings manually.
- Do not expose the unauthenticated development API to the public internet.

## License

See the repository's license file.
