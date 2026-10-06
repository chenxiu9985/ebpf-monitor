"""Real Linux capture test. Requires a built collector and permission to load BPF."""
import argparse
import json
import os
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.model import load_config
from monitor.runtime import doctor
from monitor.storage import Store, report


def wait_for(predicate, process, seconds=10):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if predicate():
            return
        if process.poll() is not None:
            raise RuntimeError(f"process exited early: {process.returncode}")
        time.sleep(0.05)
    raise RuntimeError("timed out waiting for readiness")


def stop(process):
    if process and process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="out/integration")
    p.add_argument("--repetitions", type=int, default=1)
    p.add_argument("--uid", type=int, default=os.getuid())
    p.add_argument("--capture-mappings", action="store_true")
    p.add_argument("--response-ready-fixture", action="store_true")
    p.add_argument("--response-mode", choices=["audit", "shadow"], default="audit")
    args = p.parse_args()
    if args.repetitions < 1 or args.uid < 0:
        p.error("invalid repetitions or uid")
    destination = Path(args.out).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if (destination / "alerts.db").exists():
        raise RuntimeError("use a new output directory per integration run")
    result = {"source": "REAL_KERNEL_CAPTURE", "environment": doctor(), "passed": False,
              "repetitions": args.repetitions, "workload_uid": args.uid}
    analyzer = collector = None
    with tempfile.TemporaryDirectory(prefix="ebpf-monitor-") as temporary:
        temp = Path(temporary)
        temp.chmod(0o755)
        service, worker, library = temp / "service", temp / "worker", temp / "benign.so"
        protected = temp / "protected.txt"
        protected.write_text("synthetic test data; not an actual credential\n")
        protected.chmod(0o644)
        for source, target in (("response_service.c" if args.response_ready_fixture else "service.c", service), ("worker.c", worker)):
            subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(ROOT / "tests/fixtures" / source), "-o", str(target)], check=True)
        subprocess.run(["cc", "-shared", "-fPIC", str(ROOT / "tests/fixtures/benign_preload.c"), "-o", str(library)], check=True)
        config = {**load_config(), "service_executables": [str(service)], "sensitive_paths": [str(protected)],
                  "response_mode": args.response_mode,
                  "exceptions": [{"rule": "R01", "exe": "/usr/bin/cat", "uid": args.uid},
                                 {"rule": "R03", "exe": "/usr/bin/true", "uid": args.uid}]}
        rules = destination / "rules.json"
        rules.write_text(json.dumps(config), encoding="utf-8")
        sock = temp / "events.sock"
        with (destination / "analyzer.log").open("w") as alog, (destination / "collector.log").open("w") as clog:
            try:
                analyzer = subprocess.Popen([sys.executable, "-m", "monitor", "listen", "--socket", str(sock),
                                             "--db", str(destination / "alerts.db"), "--raw", str(destination / "events.jsonl"),
                                             "--alerts", str(destination / "alerts.jsonl"), "--rules", str(rules)], cwd=ROOT, stdout=alog, stderr=alog)
                wait_for(sock.exists, analyzer)
                collector = subprocess.Popen([str(ROOT / "build/collector"), "--socket", str(sock), "--exclude-pid", str(analyzer.pid),
                                              *(["--capture-mappings"] if args.capture_mappings else [])],
                                             cwd=ROOT, stdout=clog, stderr=clog)
                wait_for(lambda: '"event_type":"monitor_start"' in (destination / "collector.log").read_text(), collector)
                def test_identity():
                    if os.getuid() == 0:
                        os.setgroups([])
                        os.setgid(args.uid)
                        os.setuid(args.uid)
                    elif os.getuid() != args.uid:
                        raise RuntimeError("cannot change workload UID without root")
                for _ in range(args.repetitions):
                    subprocess.run([str(service), str(worker), str(protected)], env={**os.environ, "LD_PRELOAD": str(library)}, preexec_fn=test_identity, check=True)
                    subprocess.run(["/usr/bin/cat", str(protected)], preexec_fn=test_identity, stdout=subprocess.DEVNULL, check=True)
                    subprocess.run(["/usr/bin/true"], env={**os.environ, "LD_PRELOAD": str(library)}, preexec_fn=test_identity, check=True)
                # Poll a WAL reader for the two correlated alerts, not an arbitrary long sleep.
                def complete():
                    try:
                        with sqlite3.connect(destination / "alerts.db", timeout=0.2) as db:
                            counts = dict(db.execute("SELECT rule,COUNT(*) FROM alerts GROUP BY rule"))
                        return all(counts.get(rule, 0) >= args.repetitions for rule in ("R01", "R02", "R03", "R04", "C01", "C02"))
                    except sqlite3.Error:
                        return False
                wait_for(complete, collector, 15)
                result["passed"] = True
            finally:
                stop(collector)
                stop(analyzer)
                result["collector_returncode"] = collector.returncode if collector else None
                result["analyzer_returncode"] = analyzer.returncode if analyzer else None
                result["passed"] = result["passed"] and result["collector_returncode"] == 0 and result["analyzer_returncode"] == 0
                if (destination / "alerts.db").exists():
                    store = Store(destination / "alerts.db")
                    all_alerts = store.alerts()
                    result["rules_seen"] = sorted({a["rule_id"] for a in all_alerts})
                    workers = {a["process_key"] for a in all_alerts if a.get("exe") == str(worker)}
                    result["worker_processes"] = len(workers)
                    result["worker_rule_counts"] = {rule: len({a["process_key"] for a in all_alerts if a["rule_id"] == rule and a.get("exe") == str(worker)}) for rule in ("R01", "R02", "R03", "R04", "C01", "C02")}
                    result["normal_fixture_alerts"] = len([a for a in all_alerts if a.get("exe") in ("/usr/bin/cat", "/usr/bin/true")])
                    result["mapping_collection_requested"] = args.capture_mappings
                    result["c02_complete_mapping_chains"] = sum(a["rule_id"] == "C02" and "file_mapping_observed" in a.get("stages", {}) for a in all_alerts)
                    result["r04_response_eligible"] = sum(a["rule_id"] == "R04" and a.get("evidence_quality", {}).get("response_eligible", False) for a in all_alerts)
                    result["response_ready_fixture"] = args.response_ready_fixture
                    result["response_mode"] = args.response_mode
                    result["shadow_requests"] = sum(r["state"] == "shadow" for r in store.responses())
                    if args.response_ready_fixture:
                        result["passed"] = result["passed"] and result["r04_response_eligible"] == args.repetitions
                    if args.response_mode == "shadow" and args.response_ready_fixture:
                        result["passed"] = result["passed"] and result["shadow_requests"] == args.repetitions
                    if args.capture_mappings:
                        result["passed"] = result["passed"] and result["c02_complete_mapping_chains"] == args.repetitions
                    delays = [a["delivery_delay_ns"]/1_000_000 for a in all_alerts if "delivery_delay_ns" in a]
                    if len(delays) >= 2:
                        quantiles = statistics.quantiles(delays, n=100, method="inclusive")
                        result["delivery_delay_ms"] = {"p50": statistics.median(delays), "p95": quantiles[94], "p99": quantiles[98]}
                    result["passed"] = result["passed"] and all(value == args.repetitions for value in result["worker_rule_counts"].values()) and result["normal_fixture_alerts"] == 0
                    report(store, destination / "report.html")
                    store.close()
                (destination / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
