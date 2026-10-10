import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from monitor import compare_files, send_alert


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

    def test_rejects_non_https_webhook_without_network_access(self):
        output = io.StringIO()
        with redirect_stdout(output), patch("monitor.urlopen") as mocked_urlopen:
            result = send_alert({"status": "CHANGES_DETECTED"}, "http://example.com/hook")
        self.assertFalse(result)
        mocked_urlopen.assert_not_called()
        self.assertIn("refused", output.getvalue().lower())

    def test_https_webhook_posts_json(self):
        class FakeResponse:
            status = 204
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        with patch("monitor.urlopen", return_value=FakeResponse()) as mocked_urlopen:
            self.assertTrue(send_alert({"status": "CLEAN"}, "https://alerts.example/hook"))
        request = mocked_urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://alerts.example/hook")
        self.assertEqual(request.get_method(), "POST")


if __name__ == "__main__":
    unittest.main()
