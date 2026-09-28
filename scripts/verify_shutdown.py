"""Real kernel capture: pause analysis, stop capture, resume and verify commit ACK."""
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
from monitor.runtime import doctor
from scripts.integration import stop, wait_for


def messages(path):
    rows = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows


def scenario(out, resume, opens):
    out.mkdir()
    result = {"name": "resume_during_drain" if resume else "ack_timeout", "passed": False}
    analyzer = collector = None
    with tempfile.TemporaryDirectory(prefix="v3-shutdown-") as directory:
        temp = Path(directory)
        sock = temp / "events.sock"
        fixture = temp / "fixture.txt"
        fixture.write_text("harmless shutdown workload\n")
        with (out / "analyzer.log").open("w") as alog, (out / "collector.log").open("w") as clog:
            try:
                analyzer = subprocess.Popen([sys.executable, "-m", "monitor", "listen", "--socket", str(sock),
                    "--db", str(out / "alerts.db"), "--raw", str(out / "events.jsonl"),
                    "--no-snapshot", "--exit-on-stop"], cwd=ROOT, stdout=alog, stderr=alog)
                wait_for(sock.exists, analyzer)
                collector = subprocess.Popen([str(ROOT / "build/collector"), "--socket", str(sock),
                    "--exclude-pid", str(analyzer.pid), "--drain-timeout-ms", "5000" if resume else "150"],
                    cwd=ROOT, stdout=clog, stderr=clog)
                wait_for(lambda: '"event_type":"monitor_start"' in (out / "collector.log").read_text(), collector)
                analyzer.send_signal(signal.SIGSTOP)
                for _ in range(opens if resume else 50):
                    fd = os.open(fixture, os.O_RDONLY)
                    os.close(fd)
                collector.send_signal(signal.SIGTERM)
                started = time.monotonic()
                if resume:
                    time.sleep(0.25)
                    analyzer.send_signal(signal.SIGCONT)
                collector.wait(timeout=8)
                result["shutdown_seconds"] = time.monotonic() - started
                rows = messages(out / "collector.log")
                result["shutdown"] = next((r for r in reversed(rows) if "shutdown_unsent" in r), {})
                result["final_metrics"] = next((r["metrics"] for r in reversed(rows) if "metrics" in r), {})
                if resume:
                    analyzer.wait(timeout=5)
                    with sqlite3.connect(out / "alerts.db") as db:
                        stops = db.execute("SELECT body FROM events WHERE json_extract(body,'$.event_type')='monitor_stop'").fetchall()
                        result["persisted_stop_count"] = len(stops)
                        result["persisted_events"] = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                    result["passed"] = (collector.returncode == 0 and analyzer.returncode == 0
                        and len(stops) == 1 and result["shutdown"].get("shutdown_acknowledged") is True
                        and result["shutdown"].get("shutdown_unsent") == 0 and result["shutdown"].get("shutdown_error") == 0)
                else:
                    result["passed"] = (collector.returncode != 0
                        and result["shutdown"].get("shutdown_acknowledged") is False
                        and result["shutdown"].get("shutdown_error", 0) != 0)
            finally:
                if analyzer and analyzer.poll() is None:
                    analyzer.send_signal(signal.SIGCONT)
                stop(collector)
                stop(analyzer)
                result["collector_exit"] = collector.returncode if collector else None
                result["analyzer_exit"] = analyzer.returncode if analyzer else None
                (out / "result.json").write_text(json.dumps(result, indent=2))
    return result


def supervisor_signal(out):
    logpath = out / "supervisor.log"
    session = out / "session"
    with logpath.open("w") as log:
        process = subprocess.Popen([sys.executable, str(ROOT / "scripts/run_live.py"), "--out", str(session)],
                                   cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
        try:
            wait_for(lambda: (session / "collector.log").exists() and
                '"event_type":"monitor_start"' in (session / "collector.log").read_text(), process)
            # Model terminal Ctrl+C to the foreground group, not just one PID.
            os.killpg(process.pid, signal.SIGINT)
            process.wait(timeout=18)
        finally:
            stop(process)
    result = json.loads((session / "session.json").read_text())
    result["supervisor_exit"] = process.returncode
    result["passed"] = result["passed"] and process.returncode == 0 and result["stop_requested"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--opens", type=int, default=10000)
    args = parser.parse_args()
    if not 1 <= args.opens <= 100000:
        parser.error("opens must be 1..100000")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    result = {"source": "REAL_KERNEL_SHUTDOWN", "environment": doctor(), "cases": []}
    try:
        result["cases"].append(scenario(out / "resume", True, args.opens))
        result["cases"].append(scenario(out / "timeout", False, args.opens))
        result["cases"].append(supervisor_signal(out))
    finally:
        result["passed"] = len(result["cases"]) == 3 and all(c["passed"] for c in result["cases"])
        (out / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
