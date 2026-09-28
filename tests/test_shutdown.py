"""Real C transport, Unix sockets, SQLite and process exit; no BPF privileges."""
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from monitor.protocol import Decoder, encode
from monitor.scenarios import event

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc"), "Linux and C compiler required")
class ShutdownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="monitor-transport-build-")
        cls.client = Path(cls.build.name) / "transport-client"
        subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", str(ROOT / "tests/fixtures/transport_client.c"),
                        "-o", str(cls.client)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def peer(self, reply=b"COMMITTED fixture:stop\n", count=17000, delay=0.15, timeout=10000):
        with tempfile.TemporaryDirectory(prefix="monitor-peer-") as directory:
            path = str(Path(directory) / "events.sock")
            rows, errors = [], []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(path)
                server.listen(1)
                server.settimeout(5)
                def receive():
                    try:
                        conn, _ = server.accept()
                        with conn:
                            conn.settimeout(5)
                            time.sleep(delay)
                            decoder = Decoder()
                            while True:
                                data = conn.recv(8192)
                                if not data:
                                    decoder.finish()
                                    break
                                rows.extend(decoder.feed(data))
                            if reply is None:
                                time.sleep(0.3)
                            else:
                                for i in range(0, len(reply), 3):
                                    conn.sendall(reply[i:i+3])
                    except (OSError, ValueError) as exc:
                        errors.append(exc)
                thread = threading.Thread(target=receive)
                thread.start()
                process = subprocess.run([str(self.client), path, str(timeout), str(count)],
                                         text=True, capture_output=True, timeout=6)
                thread.join(timeout=6)
                self.assertFalse(thread.is_alive())
            return process, json.loads(process.stdout), rows, errors

    def test_slow_reader_drains_more_than_queue_capacity_and_fragmented_ack(self):
        process, summary, rows, errors = self.peer()
        self.assertEqual(errors, [])
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(summary, {"error": 0, "unsent": 0, "lost": 0, "disconnects": 0})
        self.assertEqual(len(rows), 17001)
        self.assertEqual([r["event_id"] for r in rows[:-1]], [f"fixture:{i}" for i in range(17000)])
        self.assertEqual(rows[-1]["event_type"], "monitor_stop")

    def test_missing_ack_is_failure_even_when_queue_is_empty(self):
        process, summary, _, _ = self.peer(reply=None, count=1, delay=0, timeout=100)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(summary["unsent"], 0)
        self.assertNotEqual(summary["error"], 0)

    def test_wrong_ack_is_not_accepted(self):
        process, summary, _, _ = self.peer(reply=b"COMMITTED wrong:session\n", count=1, delay=0)
        self.assertEqual(process.returncode, 1)
        self.assertNotEqual(summary["error"], 0)

    def test_peer_disconnect_before_ack_is_failure(self):
        process, summary, _, _ = self.peer(reply=b"", count=1, delay=0)
        self.assertEqual(process.returncode, 1)
        self.assertNotEqual(summary["error"], 0)

    def test_stalled_reader_has_bounded_failure(self):
        start = time.monotonic()
        process, summary, _, _ = self.peer(reply=None, count=1500, delay=0.3, timeout=80)
        self.assertEqual(process.returncode, 1)
        self.assertNotEqual(summary["error"], 0)
        self.assertTrue(summary["unsent"] or summary["lost"])
        self.assertLess(time.monotonic() - start, 3)

    def start_listener(self, root, raw=None):
        log = (root / "listener.log").open("w")
        process = subprocess.Popen([sys.executable, "-m", "monitor", "listen",
            "--socket", str(root / "events.sock"), "--db", str(root / "alerts.db"),
            "--raw", str(raw or root / "events.jsonl"), "--alerts", str(root / "alerts.jsonl"),
            "--no-snapshot", "--exit-on-stop"], cwd=ROOT, stdout=log, stderr=log)
        self.addCleanup(log.close)
        def cleanup():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        self.addCleanup(cleanup)
        until = time.monotonic() + 5
        while not (root / "events.sock").exists():
            if process.poll() is not None or time.monotonic() > until:
                self.fail((root / "listener.log").read_text())
            time.sleep(0.02)
        return process

    def test_ack_proves_database_and_logs_flushed_before_exit(self):
        with tempfile.TemporaryDirectory(prefix="monitor-ack-") as directory:
            root = Path(directory)
            listener = self.start_listener(root)
            client = subprocess.run([str(self.client), str(root / "events.sock"), "5000", "1500"],
                                    capture_output=True, text=True, timeout=8)
            self.assertEqual(client.returncode, 0, client.stdout + client.stderr)
            # A separate connection observes committed rows as soon as ACK arrives.
            with sqlite3.connect(root / "alerts.db") as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1501)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
            self.assertEqual(len((root / "events.jsonl").read_text().splitlines()), 1501)
            self.assertEqual(len((root / "alerts.jsonl").read_text().splitlines()), 1)
            self.assertEqual(listener.wait(timeout=3), 0)

    def test_truncated_tail_never_acknowledged(self):
        with tempfile.TemporaryDirectory(prefix="monitor-truncated-") as directory:
            root = Path(directory)
            listener = self.start_listener(root)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(3)
                conn.connect(str(root / "events.sock"))
                conn.sendall(encode(event(1, "monitor_stop", shutdown_ack_required=True)) + b"\x00\x00")
                conn.shutdown(socket.SHUT_WR)
                self.assertEqual(conn.recv(512), b"")
            self.assertNotEqual(listener.wait(timeout=3), 0)

    def test_eof_without_stop_fails_supervised_listener(self):
        with tempfile.TemporaryDirectory(prefix="monitor-no-stop-") as directory:
            root = Path(directory)
            listener = self.start_listener(root)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.connect(str(root / "events.sock"))
                conn.sendall(encode(event(1, "file_open", path="/etc/hostname")))
            self.assertNotEqual(listener.wait(timeout=3), 0)

    def test_log_flush_failure_does_not_send_commit_ack(self):
        with tempfile.TemporaryDirectory(prefix="monitor-full-") as directory:
            root = Path(directory)
            listener = self.start_listener(root, raw="/dev/full")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(3)
                conn.connect(str(root / "events.sock"))
                conn.sendall(encode(event(1, "file_open", path="/etc/shadow"))
                             + encode(event(2, "monitor_stop", shutdown_ack_required=True)))
                conn.shutdown(socket.SHUT_WR)
                self.assertEqual(conn.recv(512), b"")
            self.assertNotEqual(listener.wait(timeout=3), 0)


if __name__ == "__main__":
    unittest.main()
