import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import dashboard_api
import integrity


class DashboardApiTests(unittest.TestCase):
    def test_scan_now_returns_no_baseline_without_fabricating_clean_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.txt").write_text("safe")
            with patch.object(dashboard_api, "TARGET", root), \
                 patch.object(dashboard_api, "BASELINE", root / "missing-baseline.json"), \
                 patch.object(integrity, "BASELINE", root / "missing-baseline.json"):
                report = dashboard_api.scan_now()
            self.assertEqual(report["status"], "NO_BASELINE")
            self.assertIn("message", report)

    def test_scan_now_includes_anomaly_analysis_and_persists_report(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as state_tmp:
            root = Path(tmp)
            (root / "normal.txt").write_text("normal")
            (root / "backdoor_payload.sh").write_text("review")
            state = Path(state_tmp)
            baseline_path = state / "baseline.json"
            reports_path = state / "reports"
            # Keep a clean reference entry; the added suspicious path should be surfaced.
            baseline_data = {
                "root": str(root),
                "created_at": "2026-01-01T00:00:00+00:00",
                "files": {"normal.txt": __import__("hashlib").sha256(b"normal").hexdigest()},
            }
            key = __import__("os").environ.get("CYBER_SENTINEL_BASELINE_KEY")
            if key:
                baseline_data["hmac_sha256"] = integrity._baseline_signature(
                    baseline_data, key
                )
            baseline_path.write_text(json.dumps(baseline_data))
            with patch.object(dashboard_api, "TARGET", root), \
                 patch.object(dashboard_api, "BASELINE", baseline_path), \
                 patch.object(dashboard_api, "REPORTS", reports_path), \
                 patch.object(integrity, "BASELINE", baseline_path), \
                 patch.object(integrity, "REPORTS", reports_path):
                report = dashboard_api.scan_now()
            self.assertEqual(report["status"], "CHANGES_DETECTED")
            self.assertEqual(report["summary"]["added"], 1)
            self.assertEqual(report["anomaly_detection"]["anomaly_count"], 1)
            self.assertTrue(list(reports_path.glob("api_*.json")))


if __name__ == "__main__":
    unittest.main()
