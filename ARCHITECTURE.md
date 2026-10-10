# Cyber Sentinel AI — Architecture

## Overview
Cyber Sentinel AI is a Python-based defensive security project for
file integrity monitoring and suspicious-file anomaly triage.

## Core Components
- `integrity.py`: SHA-256-based file integrity checks and baseline handling.
- `anomaly_detection.py`: File-feature analysis, anomaly triage, and heuristic fallback.
- `dashboard_api.py`: Local API endpoints for status and scan requests.
- `evaluate_anomaly_detection.py`: Synthetic benchmark and metric evaluation.
- `ml_evaluation_report.json`: Saved synthetic evaluation results.
- `tests/`: Automated tests for project behavior.

## High-Level Data Flow
1. An administrator initiates a scan.
2. The scan checks files against a trusted integrity baseline.
3. File characteristics and suspicious indicators are evaluated.
4. Findings are returned for administrator review.
5. Automated tests and the synthetic evaluator help verify behavior.

## Baseline Security
The baseline and HMAC key are stored locally. Protect the key and never
commit secrets. Baseline signing does not protect against every form of
host compromise.

## API Security
Keep the API bound to localhost unless proper authentication, TLS, and
network access controls have been implemented and reviewed.

## Evaluation Limitations
- Synthetic labels are based on filenames, not verified malware samples.
- Isolation Forest is unsupervised and is not trained on these labels.
- Heuristic fallback may be used when scikit-learn is unavailable.
- Synthetic benchmark metrics do not establish real-world malware
  detection accuracy or generalization.
- An anomaly score is a review-priority signal, not a malware probability.

## Scope
This project is a defensive file-integrity and anomaly-triage prototype.
It is not a complete antivirus or endpoint detection and response system.
