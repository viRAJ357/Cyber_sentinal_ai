# Cyber Sentinel AI

A defensive cybersecurity learning project for Termux and Python. It checks file integrity against a trusted SHA-256 baseline, writes JSON reports, can poll for unexpected changes, and provides an optional local API for a dashboard.

> This is an educational prototype, not an antivirus, EDR, or a guarantee that a system is secure. A hash mismatch shows a file changed; it does not prove the change was malicious.

## Features

- Basic Termux security audit and SSH permission checks (`sentinel.py`)
- SHA-256 file integrity baseline and comparison (`integrity.py`)
- JSON scan reports stored under `~/.cyber-sentinel-ai/reports/`
- Polling monitor with console alerts and HTTPS-only optional webhook notifications (`monitor.py`)\n- Explainable anomaly triage: Isolation Forest when optional scikit-learn is installed, otherwise a transparent heuristic fallback (`anomaly_detection.py`)
- Local dashboard API for on-demand scans and latest report (`dashboard_api.py`)
- Unit tests and GitHub Actions CI

## Quick start (Termux)

```sh
cd ~/cyber-sentinel-ai
python -m unittest discover -s tests -v
python sentinel.py
```

Create a baseline **once you have verified the folder is in a trusted state**:

```sh
python integrity.py baseline ~/cyber-sentinel-ai
```

Check the folder later:

```sh
python integrity.py check ~/cyber-sentinel-ai
```

Exit codes: `0` = clean, `1` = changes detected, `2` = operational error/incomplete scan.

## Continuous polling and alerts

```sh
python monitor.py ~/cyber-sentinel-ai --interval 10
```

The monitor checks every 10 seconds and prints an alert when it detects a change from the baseline. It does not automatically update the baseline. The anomaly triage ranks changed paths using file/path metadata; it is not a malware classifier and can produce false positives. The core tool works without scikit-learn.

Optional webhook (must be HTTPS; use only an endpoint you control and keep the URL private):

```sh
export CYBER_SENTINEL_WEBHOOK_URL="https://your-approved-webhook.example/endpoint"
python monitor.py ~/cyber-sentinel-ai --interval 10
```

Use `--once` to run a single monitor check and return the same exit codes:

```sh
python monitor.py ~/cyber-sentinel-ai --once
```

## Optional machine-learning dependency\n\nFor Isolation Forest-based anomaly triage, install the optional dependency in a virtual environment:\n\n```sh\npython -m pip install -r requirements-ml.txt\n```\n\nWithout it, the monitor uses the explainable heuristic fallback. Install dependencies only from sources you trust.\n\n## Dashboard API (local development)

Set up a baseline first. Start the API in Termux:

```sh
cd ~/cyber-sentinel-ai
CYBER_SENTINEL_TARGET="$HOME/cyber-sentinel-ai" python dashboard_api.py
```

It listens on `http://127.0.0.1:8765` only. Routes:

- `GET /api/status` — latest saved report
- `POST /api/scan` — run a scan and save a JSON report

Keep it on localhost. This development API does not implement user authentication, rate limiting or TLS and must not be exposed directly to the public internet. The dashboard CORS setting is not a substitute for authentication.

### Connecting the public GitHub Pages UI

The static site at `https://viraj357.github.io/Cyber_sentinal_ai/` cannot access a Termux server running on your phone by itself. To use live data from the public site, deploy the API on a trusted HTTPS host, add authentication and rate limiting, configure CORS for your exact dashboard origin, and set the dashboard's API URL to that hosted endpoint. Do not publish an unauthenticated scan endpoint that exposes local files or reports. Until then, use the local API for development and the site will correctly indicate when it is disconnected.

## Baseline safety

- Create the baseline from a known-good folder.
- Back up the baseline securely; the current baseline is stored at `~/.cyber-sentinel-ai/integrity_baseline.json`.
- A local attacker with the same account may be able to alter both the files and the baseline. For stronger protection, store a signed/off-device baseline and restrict write access.
- Do not run scans against systems or files you do not own or have permission to audit.

## Tests

```sh
python -m unittest discover -s tests -v
```
