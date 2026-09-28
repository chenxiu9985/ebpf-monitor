"""Reject diagnostic/monitoring combinations before any privileged BPF load."""
import os
import subprocess
import unittest
from pathlib import Path

COLLECTOR = Path(__file__).resolve().parents[1] / "build" / "collector"


@unittest.skipUnless(os.name == "posix" and os.access(COLLECTOR, os.X_OK), "built Linux collector required")
class CollectorOptionsTests(unittest.TestCase):
    def reject(self, *args):
        result = subprocess.run([str(COLLECTOR), *args], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn('"event_type":"monitor_start"', result.stderr)

    def test_diagnostics_cannot_replace_analysis(self):
        for mode in ("kernel", "consume", "encode"):
            with self.subTest(mode=mode):
                self.reject("--benchmark-stage", mode, "--socket", "/tmp/unused-diagnostic.sock", "--exclude-pid", "1")

    def test_diagnostics_cannot_enable_enforcement(self):
        for mode in ("kernel", "consume", "encode"):
            with self.subTest(mode=mode):
                self.reject("--benchmark-stage", mode, "--enforce-cgroup", "/sys/fs/cgroup/unused-diagnostic",
                            "--enforce-uid", "1000", "--deny-open", "/tmp/unused-diagnostic")

    def test_invalid_batch_intervals_fail_before_load(self):
        for interval in ("-1", "51", "x", "9999999999999999999999999"):
            with self.subTest(interval=interval):
                self.reject("--batch-ms", interval)

    def test_invalid_shutdown_deadline_fails_before_load(self):
        for value in ("0", "-1", "60001", "x", "99999999999999999999999"):
            with self.subTest(value=value):
                self.reject("--drain-timeout-ms", value)


if __name__ == "__main__":
    unittest.main()
