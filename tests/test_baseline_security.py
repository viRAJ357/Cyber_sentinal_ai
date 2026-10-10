import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from integrity import _baseline_signature, load_baseline


class BaselineSignatureTests(unittest.TestCase):
    def _write_baseline(self, path, root, signed=False, key="test-secret-key"):
        data = {
            "root": str(root),
            "created_at": "2026-01-01T00:00:00+00:00",
            "files": {"sample.txt": "a" * 64},
        }
        if signed:
            data["hmac_sha256"] = _baseline_signature(data, key)
        path.write_text(json.dumps(data), encoding="utf-8")
        return data

    def test_valid_signed_baseline_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            baseline_path = Path(tmp) / "baseline.json"
            self._write_baseline(baseline_path, root, signed=True)
            with patch("integrity.BASELINE", baseline_path), patch.dict(
                os.environ, {"CYBER_SENTINEL_BASELINE_KEY": "test-secret-key"}
            ):
                self.assertIn("hmac_sha256", load_baseline(root))

    def test_tampered_signed_baseline_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            baseline_path = Path(tmp) / "baseline.json"
            data = self._write_baseline(baseline_path, root, signed=True)
            data["files"]["sample.txt"] = "b" * 64
            baseline_path.write_text(json.dumps(data), encoding="utf-8")
            with patch("integrity.BASELINE", baseline_path), patch.dict(
                os.environ, {"CYBER_SENTINEL_BASELINE_KEY": "test-secret-key"}
            ):
                with self.assertRaisesRegex(ValueError, "signature verification failed"):
                    load_baseline(root)

    def test_signed_baseline_requires_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            baseline_path = Path(tmp) / "baseline.json"
            self._write_baseline(baseline_path, root, signed=True)
            with patch("integrity.BASELINE", baseline_path), patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "requires CYBER_SENTINEL_BASELINE_KEY"):
                    load_baseline(root)

    def test_configured_key_rejects_unsigned_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            baseline_path = Path(tmp) / "baseline.json"
            self._write_baseline(baseline_path, root, signed=False)
            with patch("integrity.BASELINE", baseline_path), patch.dict(
                os.environ, {"CYBER_SENTINEL_BASELINE_KEY": "test-secret-key"}
            ):
                with self.assertRaisesRegex(ValueError, "baseline is unsigned"):
                    load_baseline(root)


if __name__ == "__main__":
    unittest.main()
