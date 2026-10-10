import unittest

from monitor import compare_files


class CompareFilesTests(unittest.TestCase):
    def test_reports_added_changed_and_missing_files(self):
        previous = {"same.txt": "a" * 64, "change.txt": "b" * 64, "gone.txt": "c" * 64}
        current = {"same.txt": "a" * 64, "change.txt": "d" * 64, "new.txt": "e" * 64}
        self.assertEqual(compare_files(previous, current), {
            "added": ["new.txt"],
            "missing": ["gone.txt"],
            "changed": ["change.txt"],
        })

    def test_clean_snapshot_has_empty_lists(self):
        files = {"same.txt": "a" * 64}
        self.assertEqual(compare_files(files, files), {
            "added": [], "missing": [], "changed": []
        })


if __name__ == "__main__":
    unittest.main()
