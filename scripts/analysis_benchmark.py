"""Reproducible analysis-stage benchmark; synthetic by default, never kernel evidence."""
import argparse
import hashlib
import json
import platform
import statistics
import sys
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--input", type=Path, help="optional JSONL replay input; use a matching --rules")
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--processes", type=int, default=1500)
    parser.add_argument("--opens", type=int, default=20000)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.processes <= 8192 or not 1 <= args.opens <= 1000000 or not 1 <= args.rounds <= 20:
        parser.error("invalid workload bounds")
    root = args.source_root.resolve()
    sys.path.insert(0, str(root))
    from monitor.engine import Engine
    from monitor.model import load_config
    from monitor.protocol import Decoder, encode
    from monitor.runtime import Pipeline
    from monitor.scenarios import event, malicious_chain
    from monitor.storage import Store
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    config = load_config(args.rules)
    if args.input:
        records = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip()]
        source = "JSONL_REPLAY_NOT_LIVE_CAPTURE"
    else:
        records = [event(i + 1, "process_exec", f"bench:{i}", exe="/usr/bin/worker") for i in range(args.processes)]
        records += [event(args.processes + i + 1, "file_open", f"bench:{i % args.processes}", path="/etc/hostname")
                    for i in range(args.opens)]
        for index, row in enumerate(malicious_chain(), len(records) + 1):
            row = {**row, "event_id": f"bench-chain:{index}", "monotonic_ns": index * 1000000000}
            records.append(row)
        source = "SYNTHETIC_ANALYSIS_BENCHMARK"
    wire = b"".join(encode(row) for row in records)
    result = {"source": source, "platform": platform.platform(), "python": sys.version,
              "source_root": str(root), "output_directory": str(out), "records": len(records),
              "input_sha256": hashlib.sha256(wire).hexdigest(), "config": config,
              "source_sha256": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in sorted((root / "monitor").glob("*.py"))},
              "stage_definitions": {"decode": "framed JSON bytes -> dictionaries",
                                    "engine": "complete rule engine, including process-cache population",
                                    "storage": "all event rows and final SQLite commit, no analysis",
                                    "pipeline": "validation, reorder, rules, raw/alerts JSONL and SQLite, final flush"},
              "limitation": "Sequential diagnostic stages are not additive costs. No eBPF/collector, live socket rate, or VMware claim.",
              "rounds": []}
    for run in range(args.rounds):
        row = {"round": run + 1}
        def measure(name, action):
            wall, cpu = time.perf_counter(), time.process_time()
            value = action()
            elapsed = time.perf_counter() - wall
            row[name] = {"seconds": elapsed, "cpu_seconds": time.process_time() - cpu,
                         "events_per_second": len(records) / elapsed}
            return value
        def decode():
            decoder, count = Decoder(), 0
            for offset in range(0, len(wire), 65536):
                count += len(decoder.feed(wire[offset:offset+65536]))
            decoder.finish()
            if count != len(records):
                raise RuntimeError("decode count mismatch")
        def engine():
            instance = Engine(config)
            alerts = [alert for record in records for alert in instance.process(record)]
            row["engine_alerts"] = len(alerts)
        def storage():
            store = Store(out / f"storage-{run}.db")
            try:
                for record in records:
                    store.event(record)
                store.flush()
            finally:
                store.close()
        def pipeline():
            store = Store(out / f"pipeline-{run}.db")
            try:
                pipe = Pipeline(config, store, raw=out / f"raw-{run}.jsonl", alerts=out / f"alerts-{run}.jsonl")
                for record in records:
                    pipe.push(record)
                pipe.flush()
                alerts = sorted(store.alerts(), key=lambda x: x["alert_id"])
                for alert in alerts:
                    alert.pop("storage_submit_ns", None)
                row["pipeline_alerts"] = len(alerts)
                row["alert_sha256"] = hashlib.sha256(json.dumps(alerts, sort_keys=True).encode()).hexdigest()
                row["event_rows"] = store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                row["engine_metrics"] = dict(pipe.engine.metrics)
                if row["event_rows"] != len({r["event_id"] for r in records}):
                    raise RuntimeError("stored event count mismatch")
            finally:
                store.close()
        actions = {"decode": decode, "engine": engine, "storage": storage, "pipeline": pipeline}
        names = list(actions)
        for name in names[run % 4:] + names[:run % 4]:
            measure(name, actions[name])
        result["rounds"].append(row)
    result["median_seconds"] = {name: statistics.median(r[name]["seconds"] for r in result["rounds"])
                                for name in ("decode", "engine", "storage", "pipeline")}
    result["passed"] = len({r["alert_sha256"] for r in result["rounds"]}) == 1
    (out / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"source": source, "records": len(records), "median_seconds": result["median_seconds"],
                      "passed": result["passed"], "result": str(out / "result.json")}, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
