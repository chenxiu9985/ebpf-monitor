import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.acceptance_storage import (
    RESERVE_BYTES, archive_results, check_storage, required_storage, save_result,
)


class AcceptanceStorageTests(unittest.TestCase):
    def test_budget_tracks_duration_and_rate(self):
        self.assertEqual(required_storage(3600, 1000) - RESERVE_BYTES,
                         10 * (required_storage(3600, 100) - RESERVE_BYTES))

    def test_low_space_rejected_and_reserve_boundary_allowed(self):
        with patch("scripts.acceptance_storage.shutil.disk_usage",
                   return_value=SimpleNamespace(free=RESERVE_BYTES - 1)):
            with self.assertRaisesRegex(OSError, "Insufficient free space"):
                check_storage(".")
        with patch("scripts.acceptance_storage.shutil.disk_usage",
                   return_value=SimpleNamespace(free=RESERVE_BYTES)):
            self.assertEqual(check_storage("."), RESERVE_BYTES)

    def test_same_filesystem_archive_moves_without_second_copy(self):
        with tempfile.TemporaryDirectory() as root:
            source, destination = Path(root)/"source", Path(root)/"destination"
            source.mkdir(); (source/"evidence").write_bytes(b"original evidence")
            with patch("scripts.acceptance_storage.shutil.copytree") as copying:
                self.assertEqual(archive_results(source, destination), "rename")
                copying.assert_not_called()
            self.assertFalse(source.exists())
            self.assertEqual((destination/"evidence").read_bytes(), b"original evidence")

    def test_failed_archive_preserves_source(self):
        with tempfile.TemporaryDirectory() as root:
            source, destination = Path(root)/"source", Path(root)/"destination"
            source.mkdir(); (source/"evidence").write_bytes(b"original evidence")
            with patch.object(Path, "rename", side_effect=OSError("disk full")):
                with self.assertRaises(OSError): archive_results(source, destination)
            self.assertEqual((source/"evidence").read_bytes(), b"original evidence")

    def test_existing_destination_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as root:
            source, destination = Path(root)/"source", Path(root)/"destination"
            source.mkdir(); destination.mkdir()
            with self.assertRaises(FileExistsError): archive_results(source, destination)
            self.assertTrue(source.exists())

    def test_result_write_failure_prints_result(self):
        output = io.StringIO()
        with patch.object(Path, "write_text", side_effect=OSError("disk full")), contextlib.redirect_stdout(output):
            self.assertFalse(save_result("result.json", {"passed": False, "error": "disk full"}))
        self.assertIn('"passed": false', output.getvalue())


if __name__ == "__main__":
    unittest.main()
