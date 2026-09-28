"""Real listener/signals with synthetic wire events, not a kernel capture test."""
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from monitor.engine import Engine
from monitor.model import load_config
from monitor.protocol import encode
from monitor.scenarios import event


class ReloadTests(unittest.TestCase):
    def test_nested_invalid_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "rules.json"
            for data in ({"enabled": [[]]}, {"exceptions": [{"rule": [], "exe": "/x", "uid": 1000}]}):
                config.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    load_config(config)

    @unittest.skipUnless(os.name == "posix", "Linux device/inode encoding")
    def test_reload_refreshes_sensitive_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "first", Path(directory) / "second"
            first.touch()
            second.touch()
            engine = Engine({**load_config(), "sensitive_paths": [str(first)]})
            before = dict(engine.sensitive_objects)
            engine.reload({**load_config(), "version": 2, "sensitive_paths": [str(second)]})
            self.assertNotEqual(before, engine.sensitive_objects)
            self.assertEqual(list(engine.sensitive_objects.values()), [str(second)])

    @unittest.skipUnless(hasattr(signal, "SIGHUP") and hasattr(socket, "AF_UNIX"), "Linux listener required")
    def test_live_reload_rejections_preserve_rules_and_idle_reload_applies(self):
        with tempfile.TemporaryDirectory(prefix="monitor-reload-") as directory:
            root = Path(directory)
            config = root / "rules.json"
            config.write_text(json.dumps({"version": 1}))
            logpath = root / "listener.log"
            def wait_for(check):
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if check():
                        return
                    if process.poll() is not None:
                        self.fail(logpath.read_text())
                    time.sleep(0.02)
                self.fail("listener progress timed out: " + logpath.read_text())
            with logpath.open("w") as log:
                process = subprocess.Popen([sys.executable, "-m", "monitor", "listen", "--socket", str(root / "events.sock"),
                    "--db", str(root / "alerts.db"), "--raw", str(root / "events.jsonl"), "--rules", str(config)], stdout=log, stderr=log)
                try:
                    wait_for(lambda: (root / "events.sock").exists())
                    # Reload also works while there is no collector connection.
                    config.write_text(json.dumps({"version": 2}))
                    process.send_signal(signal.SIGHUP)
                    wait_for(lambda: '"rule_reload": "applied"' in logpath.read_text())
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                        connection.connect(str(root / "events.sock"))
                        for index, invalid in enumerate((None, "enabled: [", json.dumps({"enabled": [[]]})), 1):
                            if invalid is None:
                                config.unlink()
                            else:
                                config.write_text(invalid)
                            process.send_signal(signal.SIGHUP)
                            wait_for(lambda: logpath.read_text().count('"rule_reload": "rejected"') >= index)
                        connection.sendall(encode(event(1, "file_open", path="/etc/shadow")))
                        def alerted():
                            with sqlite3.connect(root / "alerts.db") as db:
                                return db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
                        wait_for(alerted)
                finally:
                    if process.poll() is None:
                        process.send_signal(signal.SIGTERM)
                    process.wait(timeout=8)
            self.assertEqual(process.returncode, 0)
            with sqlite3.connect(root / "alerts.db") as db:
                alert = json.loads(db.execute("SELECT body FROM alerts").fetchone()[0])
            self.assertEqual(alert["rule_version"], 2)
            self.assertEqual(alert["rule_id"], "R01")


if __name__ == "__main__":
    unittest.main()
