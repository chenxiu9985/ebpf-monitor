"""Pause only our analyzer, force bounded queue overflow, then verify recovery."""
import argparse
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.integration import wait_for, stop


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="out/recovery")
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if (out / "result.json").exists():
        raise RuntimeError("choose a fresh output directory")
    result = {"source": "REAL_TRANSPORT_OVERLOAD", "passed": False}
    analyzer = collector = None
    with tempfile.TemporaryDirectory(prefix="ebpf-recovery-") as directory:
        temp = Path(directory)
        socket = temp / "events.sock"
        file = temp / "fixture"
        file.write_text("harmless\n")
        with (out / "analyzer.log").open("w") as alog, (out / "collector.log").open("w") as clog:
            try:
                analyzer = subprocess.Popen([sys.executable, "-m", "monitor", "listen", "--socket", str(socket),
                                             "--db", str(out / "alerts.db"), "--raw", str(out / "events.jsonl")], cwd=ROOT, stdout=alog, stderr=alog)
                wait_for(socket.exists, analyzer)
                collector = subprocess.Popen([str(ROOT / "build/collector"), "--socket", str(socket), "--exclude-pid", str(analyzer.pid)], stdout=clog, stderr=clog)
                wait_for(lambda: '"event_type":"monitor_start"' in (out / "collector.log").read_text(), collector)
                analyzer.send_signal(signal.SIGSTOP)
                started = time.monotonic()
                for _ in range(20000):
                    fd = os.open(file, os.O_RDONLY)
                    os.close(fd)
                result["workload_seconds_while_analyzer_paused"] = time.monotonic() - started
                analyzer.send_signal(signal.SIGCONT)
                def loss_visible():
                    with sqlite3.connect(out / "alerts.db", timeout=0.5) as db:
                        return any(json.loads(row[0]).get("metrics", {}).get("queue_lost", 0) > 0
                                   for row in db.execute("SELECT body FROM events WHERE process=''"))
                wait_for(loss_visible, analyzer, 15)
                recovered = temp / "recovered-marker"
                recovered.write_text("capture after recovery\n")
                fd = os.open(recovered, os.O_RDONLY)
                os.close(fd)
                def recovered_visible():
                    with sqlite3.connect(out / "alerts.db", timeout=0.5) as db:
                        return any(json.loads(row[0]).get("path") == str(recovered) for row in db.execute("SELECT body FROM events ORDER BY time DESC LIMIT 500"))
                wait_for(recovered_visible, analyzer, 10)
                result["passed"] = True
            finally:
                if analyzer and analyzer.poll() is None:
                    analyzer.send_signal(signal.SIGCONT)
                stop(collector)
                stop(analyzer)
                logs = (out / "collector.log").read_text()
                summaries = [json.loads(line) for line in logs.splitlines() if line.startswith('{"schema_version"')]
                result["final_metrics"] = summaries[-1]["metrics"] if summaries else {}
                result["collector_exit"] = collector.returncode if collector else None
                result["analyzer_exit"] = analyzer.returncode if analyzer else None
                shutdowns = [json.loads(line) for line in logs.splitlines() if line.startswith('{"shutdown_unsent"')]
                result["shutdown"] = shutdowns[-1] if shutdowns else {}
                result["passed"] = (result["passed"] and result["collector_exit"] == 0 and result["analyzer_exit"] == 0
                    and result["shutdown"].get("shutdown_unsent") == 0
                    and result["shutdown"].get("shutdown_acknowledged") is True)
                (out / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
