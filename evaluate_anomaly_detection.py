"""Evaluate Cyber Sentinel AI anomaly triage on a synthetic labeled benchmark.

This measures agreement with the benchmark's synthetic labels only. It is not a
real-world malware benchmark and does not establish production detection quality.
"""
import argparse
import json
import tempfile
from pathlib import Path

from anomaly_detection import score_events


def make_case(root, index, kind):
    """Create one synthetic changed-file event and its expected label."""
    names = {
        "benign": f"documents/report_{index}.txt",
        "suspicious": f"backdoor_payload_{index}.sh",
    }
    name = names[kind]
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("synthetic evaluation fixture\n", encoding="utf-8")
    return name, int(kind == "suspicious")


def metrics(y_true, y_pred):
    tp = sum(t == 1 and p == 1 for t, p in zip(y_true, y_pred))
    tn = sum(t == 0 and p == 0 for t, p in zip(y_true, y_pred))
    fp = sum(t == 0 and p == 1 for t, p in zip(y_true, y_pred))
    fn = sum(t == 1 and p == 0 for t, p in zip(y_true, y_pred))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(y_true) if y_true else 0.0
    return {
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def evaluate_mode(root, reference, cases, use_ml):
    y_true = []
    y_pred = []
    engine_names = set()
    rows = []
    for index, (name, label) in enumerate(cases):
        changes = {"added": [name], "changed": [], "missing": []}
        result = score_events(root, reference, reference, changes, use_ml=use_ml)
        engine_names.add(result["engine"])
        finding = result["findings"][0] if result["findings"] else {}
        prediction = int(bool(finding.get("anomaly", False)))
        y_true.append(label)
        y_pred.append(prediction)
        rows.append({
            "path": name,
            "expected_label": label,
            "predicted_anomaly": prediction,
            "score": finding.get("score", 0.0),
            "reasons": finding.get("reasons", []),
        })
    return {
        "engine": sorted(engine_names),
        "metrics": metrics(y_true, y_pred),
        "predictions": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="ml_evaluation_report.json",
                        help="Path for the JSON report (default: ml_evaluation_report.json)")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="cyber-sentinel-eval-") as temp:
        root = Path(temp)
        reference = {}
        current = {}
        for i in range(12):
            name = f"reference/file_{i:02d}.txt"
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"trusted synthetic reference {i}\n", encoding="utf-8")
            reference[name] = f"hash-{i}"
            current[name] = f"hash-{i}"

        cases = []
        for i in range(10):
            cases.append(make_case(root, i, "benign"))
            cases.append(make_case(root, i, "suspicious"))

        ml_result = evaluate_mode(root, reference, cases, use_ml=True)
        heuristic_result = evaluate_mode(root, reference, cases, use_ml=False)
        report = {
            "benchmark": "synthetic_filename_event_benchmark_v1",
            "sample_count": len(cases),
            "label_definition": {
                "0": "synthetic benign report filename",
                "1": "synthetic suspicious filename containing security keywords",
            },
            "results": {
                "ml_requested": ml_result,
                "heuristic_baseline": heuristic_result,
            },
            "limitations": [
                "Synthetic labels are based on filenames, not verified malware samples.",
                "Isolation Forest is unsupervised; its predictions are not trained on these labels.",
                "Results do not establish real-world malware detection accuracy or generalization.",
                "If scikit-learn is unavailable, ml_requested may report heuristic_fallback.",
            ],
        }
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "report": str(output),
            "sample_count": report["sample_count"],
            "ml_engine": ml_result["engine"],
            "ml_metrics": ml_result["metrics"],
            "heuristic_metrics": heuristic_result["metrics"],
            "warning": "Synthetic benchmark only; not real-world malware performance.",
        }, indent=2))


if __name__ == "__main__":
    main()
