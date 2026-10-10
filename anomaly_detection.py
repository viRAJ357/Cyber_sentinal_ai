"""Explainable anomaly scoring for file-change events.

Uses Isolation Forest when scikit-learn is installed and enough trusted reference
files are available. Otherwise falls back to explicit, reviewable heuristics.
This is a triage aid, not proof that a file is malicious.
"""
from collections import Counter
from pathlib import Path
import math

SUSPICIOUS_TERMS = ("payload", "credential", "keylog", "ransom", "stealer", "backdoor", "webshell")
EXECUTABLE_SUFFIXES = {".sh", ".bash", ".py", ".pyc", ".so", ".dll", ".exe", ".bat", ".ps1", ".apk"}
MIN_TRAINING_FILES = 8


def _entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _features(name, size, extension_counts, total_extensions):
    path = Path(name)
    parts = path.parts
    suffix = path.suffix.lower()
    ext_count = extension_counts.get(suffix, 0)
    rarity = 1.0 - (ext_count / max(total_extensions, 1))
    lowered = name.lower()
    return [
        float(len(parts)),
        float(len(path.name)),
        float(len(suffix)),
        float(any(part.startswith(".") for part in parts)),
        float(suffix in EXECUTABLE_SUFFIXES),
        float(any(term in lowered for term in SUSPICIOUS_TERMS)),
        _entropy(path.name),
        math.log1p(max(size, 0)),
        rarity,
    ]


def _file_size(root, name):
    candidate = root.joinpath(*Path(name).parts)
    try:
        if candidate.is_symlink() or not candidate.is_file():
            return 0
        return candidate.stat().st_size
    except OSError:
        return 0


def score_events(root, baseline_files, current_files, changes):
    """Return explainable anomaly findings for added/changed/missing paths."""
    root = Path(root).resolve()
    affected = set(changes.get("added", [])) | set(changes.get("changed", [])) | set(changes.get("missing", []))
    reference_names = sorted(set(baseline_files) & set(current_files) - affected)
    event_names = [(name, kind) for kind in ("added", "changed", "missing") for name in changes.get(kind, [])]
    extension_counts = Counter(Path(name).suffix.lower() for name in reference_names)
    total_extensions = max(len(reference_names), 1)

    reference_features = [
        _features(name, _file_size(root, name), extension_counts, total_extensions)
        for name in reference_names
    ]
    event_features = [
        _features(name, _file_size(root, name), extension_counts, total_extensions)
        for name, _ in event_names
    ]

    engine = "heuristic_fallback"
    predictions = [False] * len(event_names)
    scores = [0.0] * len(event_names)
    if len(reference_features) >= MIN_TRAINING_FILES and event_features:
        try:
            from sklearn.ensemble import IsolationForest
            model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
            model.fit(reference_features)
            predictions = [value == -1 for value in model.predict(event_features)]
            scores = [round(max(0.0, min(100.0, 50.0 - float(value) * 100.0)), 1)
                      for value in model.decision_function(event_features)]
            engine = "isolation_forest"
        except ImportError:
            pass
        except (ValueError, ArithmeticError):
            # Malformed/degenerate inventories should not stop integrity monitoring.
            pass

    findings = []
    for index, (name, kind) in enumerate(event_names):
        path = Path(name)
        lowered = name.lower()
        reasons = []
        if any(part.startswith(".") for part in path.parts):
            reasons.append("hidden path")
        if path.suffix.lower() in EXECUTABLE_SUFFIXES:
            reasons.append("executable or script file type")
        if any(term in lowered for term in SUSPICIOUS_TERMS):
            reasons.append("filename contains a sensitive security keyword")
        if len(path.parts) >= 6:
            reasons.append("unusually deep path")
        if len(path.name) >= 70 or _entropy(path.name) >= 4.0:
            reasons.append("unusually long or high-entropy filename")
        if engine == "heuristic_fallback":
            predictions[index] = len(reasons) >= 2 or any(
                term in lowered for term in SUSPICIOUS_TERMS
            )
            scores[index] = min(100.0, 25.0 * len(reasons) + (35.0 if predictions[index] else 0.0))
        findings.append({
            "path": name,
            "change_type": kind,
            "anomaly": bool(predictions[index]),
            "score": scores[index],
            "reasons": reasons,
        })

    return {
        "engine": engine,
        "trained_on_files": len(reference_features) if engine == "isolation_forest" else 0,
        "note": "Anomaly scores prioritize review; they do not prove malicious activity.",
        "findings": findings,
        "anomaly_count": sum(1 for finding in findings if finding["anomaly"]),
    }
