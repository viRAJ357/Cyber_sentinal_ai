import tempfile
import unittest
from pathlib import Path

from anomaly_detection import score_events


class AnomalyDetectionTests(unittest.TestCase):
    def test_flags_suspicious_filename_with_fallback_or_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "backdoor_payload.sh"
            path.write_text("echo review")
            result = score_events(
                root,
                {"normal.txt": "a" * 64},
                {"normal.txt": "a" * 64, "backdoor_payload.sh": "b" * 64},
                {"added": ["backdoor_payload.sh"], "changed": [], "missing": []},
            )
            self.assertIn(result["engine"], {"heuristic_fallback", "isolation_forest"})
            self.assertEqual(result["anomaly_count"], 1)
            self.assertTrue(result["findings"][0]["anomaly"])
            self.assertTrue(result["findings"][0]["reasons"])

    def test_clean_changes_return_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = score_events(root, {}, {}, {"added": [], "changed": [], "missing": []})
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["anomaly_count"], 0)


if __name__ == "__main__":
    unittest.main()
