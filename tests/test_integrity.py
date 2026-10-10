import tempfile
import unittest
from pathlib import Path

from integrity import scan_folder


class ScanFolderTests(unittest.TestCase):
    def test_detects_normal_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "notes.txt").write_text("safe test")
            results, errors = scan_folder(root)

            self.assertIn("notes.txt", results)
            self.assertEqual(errors, [])

    def test_ignores_generated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".git").mkdir()
            (root / ".git" / "internal").write_text("ignored")
            (root / "__pycache__").mkdir()
            (root / "__pycache__" / "module.pyc").write_bytes(b"test")
            (root / "app.pyc").write_bytes(b"test")
            (root / "keep.txt").write_text("keep")

            results, errors = scan_folder(root)

            self.assertEqual(set(results), {"keep.txt"})
            self.assertEqual(errors, [])

    def test_detects_changed_file_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file_path = root / "sample.txt"
            file_path.write_text("version one")
            first, _ = scan_folder(root)

            file_path.write_text("version two")
            second, _ = scan_folder(root)

            self.assertNotEqual(first["sample.txt"], second["sample.txt"])


if __name__ == "__main__":
    unittest.main()
