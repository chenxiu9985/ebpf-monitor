"""Controlled benign file-open rates through the complete live v3 pipeline."""
import argparse
import hashlib
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--rates", default="500,2000,5000")
    parser.add_argument("--seconds", type=int, default=3)
    args = parser.parse_args()
    rates = [int(v) for v in args.rates.split(",")]
    if not rates or any(not 1 <= v <= 100000 for v in rates) or not 1 <= args.seconds <= 60:
        parser.error("rates must be 1..100000 and seconds 1..60")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    result = {"source": "REAL_KERNEL_CONTROLLED_BENIGN_OPENS", "environment": doctor(),
              "seconds_per_rate": args.seconds, "cases": [], "passed": False,
              "collector_sha256": hashlib.sha256((ROOT / "build/collector").read_bytes()).hexdigest(),
              "limitation": "Short fixed-rate workload; not an application overhead benchmark or long-term capacity guarantee."}
    try:
        with tempfile.TemporaryDirectory(prefix="v3-load-") as temporary:
            fixture = Path(temporary) / "fixture.txt"
            fixture.write_text("harmless rate-controlled workload\n")
            for index, rate in enumerate(rates):
                case_out = out / f"rate-{index}-{rate}"
                with (out / f"supervisor-{index}.log").open("w") as log:
                    process = subprocess.Popen([sys.executable, str(ROOT / "scripts/run_live.py"), "--out", str(case_out)],
                        cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
                    issued = 0
                    try:
                        wait_for(lambda: (case_out / "collector.log").exists() and
                            '"event_type":"monitor_start"' in (case_out / "collector.log").read_text(), process)
                        started = time.monotonic()
                        target = rate * args.seconds
                        batch = min(100, max(1, rate // 100))
                        while issued < target:
                            if process.poll() is not None:
                                raise RuntimeError("monitor stopped during workload")
                            for _ in range(min(batch, target - issued)):
                                fd = os.open(fixture, os.O_RDONLY)
                                os.close(fd)
                                issued += 1
                            pause = started + issued / rate - time.monotonic()
                            if pause > 0:
                                time.sleep(pause)
                        elapsed = time.monotonic() - started
                        os.killpg(process.pid, signal.SIGINT)
                        process.wait(timeout=18)
                    finally:
                        stop(process)
                session = json.loads((case_out / "session.json").read_text())
                with sqlite3.connect(case_out / "alerts.db") as db:
                    captured = db.execute("SELECT COUNT(*) FROM events WHERE json_extract(body,'$.event_type')='file_open' "
                                          "AND json_extract(body,'$.path')=?", (str(fixture),)).fetchone()[0]
                case = {"target_opens_per_second": rate, "issued": issued, "captured_fixture_opens": captured,
                        "workload_seconds": elapsed, "actual_opens_per_second": issued / elapsed,
                        "supervisor_exit": process.returncode, "session": session,
                        "passed": process.returncode == 0 and session["passed"] and session["capture_loss_free"] and captured == issued}
                result["cases"].append(case)
                print(json.dumps({k: v for k, v in case.items() if k != "session"}), flush=True)
        result["passed"] = len(result["cases"]) == len(rates) and all(c["passed"] for c in result["cases"])
    finally:
        (out / "result.json").write_text(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
