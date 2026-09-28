"""B0/B1 microbenchmark with optional consume/encode diagnostics; no production overhead claim."""
import argparse
import hashlib
import resource
import json
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.runtime import doctor


def workload(file, opens, execs):
    started = time.perf_counter()
    for _ in range(opens):
        fd = os.open(file, os.O_RDONLY)
        os.close(fd)
    for _ in range(execs):
        subprocess.run(["/usr/bin/true"], check=True)
    return time.perf_counter() - started


def collector_cpu(pid):
    # stat comm can contain spaces or parentheses; fields after the final ')' are stable.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="out/benchmark")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--opens", type=int, default=2000)
    parser.add_argument("--execs", type=int, default=100)
    parser.add_argument("--profile", action="store_true", help="compare B0, kernel-only P0, consume-only P1, encode-discard P2, and JSONL B1")
    parser.add_argument("--environment-label", default="unspecified", help="e.g. vmware or wsl; recorded, not inferred")
    parser.add_argument("--batch-ms", type=int, default=10, choices=range(51), help="ring batching interval; 0 restores adaptive notifications")
    parser.add_argument("--compare-batching", action="store_true", help="rotate B0, B1-unbatched, B1 with one collector binary")
    parser.add_argument("--compare-records", action="store_true", help="rotate B0, B1-full padded records, B1 compact records")
    args = parser.parse_args()
    if args.compare_records and (args.compare_batching or args.profile):
        parser.error("record comparison cannot combine with other comparisons")
    if args.compare_batching and (args.profile or args.batch_ms == 0):
        parser.error("batch comparison requires a nonzero interval and cannot combine with --profile")
    if min(args.rounds, args.opens, args.execs) < 1:
        parser.error("all counts must be positive")
    destination = Path(args.out).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    groups = ["B0", "P0", "P1", "P2", "B1"] if args.profile else ["B0", "B1"]
    if args.compare_batching:
        groups = ["B0", "B1-unbatched", "B1"]
    if args.compare_records:
        groups = ["B0", "B1-full", "B1"]
    manifest = {}
    for directory in ("bpf", "collector", "monitor", "scripts", "tests", "rules", "config"):
        for f in sorted((ROOT / directory).rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                manifest[f.relative_to(ROOT).as_posix()] = hashlib.sha256(f.read_bytes()).hexdigest()
    manifest["build/collector"] = hashlib.sha256((ROOT / "build/collector").read_bytes()).hexdigest()
    result = {"source": "LOCAL_MICROBENCHMARK", "environment": doctor(), "parameters": vars(args), "rounds": [],
              "source_sha256": manifest, "output_directory": str(destination),
              "group_definitions": {"B0": "no collector", "P0": "kernel construction/pairing/counters; ring output disabled", "P1": "all probes + ring transport + consume; no JSON encoding", "P2": "P1 + JSON encoding discarded before output", "B1": "all probes + JSONL output, no analyzer", "B1-unbatched": "same binary with batch-ms=0; adaptive notifications + JSONL"},
              "limitation": "Microbenchmark on the recorded environment; no analyzer, no application workload. Stage differences are diagnostic comparisons, not additive causal cost estimates."}
    result["group_definitions"]["B1-full"] = "same collector binary with full padded ring records; JSONL output, no analyzer"
    with tempfile.TemporaryDirectory(prefix="ebpf-bench-") as directory:
        file = Path(directory) / "file"
        file.write_text("benchmark fixture\n")
        workload(file, 100, 5)
        for index in range(args.rounds):
            # Rotate stage order; preserve alternating B0/B1 for legacy runs.
            order = groups[index % len(groups):] + groups[:index % len(groups)]
            for group in order:
                collector = None
                raw = log = None
                row = {"round": index+1, "group": group}
                usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
                try:
                    if group != "B0":
                        raw = (destination / f"round-{index+1}-{group}.jsonl").open("w")
                        logpath = destination / f"round-{index+1}-{group}.log"
                        log = logpath.open("w")
                        row["batch_ms"] = 0 if group == "B1-unbatched" else args.batch_ms
                        command = [str(ROOT / "build/collector"), "--batch-ms", str(row["batch_ms"])]
                        if group == "B1-full":
                            command += ["--full-event-records"]
                        if group in ("P0", "P1", "P2"):
                            command += ["--benchmark-stage", {"P0": "kernel", "P1": "consume", "P2": "encode"}[group]]
                        collector = subprocess.Popen(command, stdout=raw, stderr=log)
                        deadline = time.monotonic()+10
                        while '"event_type":"monitor_start"' not in logpath.read_text():
                            if collector.poll() is not None or time.monotonic() > deadline:
                                raise RuntimeError("collector failed to start")
                            time.sleep(0.05)
                    cpu_before = collector_cpu(collector.pid) if collector else None
                    workload_started = time.perf_counter()
                    row["seconds"] = workload(file, args.opens, args.execs)
                    row["operations_per_second"] = (args.opens+args.execs)/row["seconds"]
                    if collector:
                        row["collector_cpu_seconds_during_workload"] = collector_cpu(collector.pid) - cpu_before
                        status = Path(f"/proc/{collector.pid}/status").read_text()
                        row["collector_rss_kib"] = next(int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:"))
                finally:
                    if collector and collector.poll() is None:
                        collector.send_signal(signal.SIGTERM)
                        try:
                            collector.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            collector.kill()
                            collector.wait()
                            raise RuntimeError("collector shutdown timed out")
                    if raw:
                        raw.close()
                    if log:
                        log.close()
                row["completion_seconds"] = time.perf_counter() - workload_started
                row["drain_and_shutdown_seconds"] = row["completion_seconds"] - row["seconds"]
                if group != "B0":
                    summaries = [json.loads(line) for line in logpath.read_text().splitlines() if line.startswith('{"schema_version"')]
                    stops = [e for e in summaries if e.get("event_type") == "monitor_stop"]
                    if collector.returncode or not stops:
                        raise RuntimeError("collector failed or final metrics missing")
                    row["final_metrics"] = stops[-1]["metrics"]
                    row["raw_bytes"] = (destination / f"round-{index+1}-{group}.jsonl").stat().st_size
                    row["capture_loss_free"] = all(row["final_metrics"][k] == 0 for k in ("ring_lost", "map_fail", "queue_lost", "unpaired"))
                    if group in ("P0", "P1", "P2"):
                        row["diagnostic_only"] = True
                        diagnostic = [json.loads(line) for line in logpath.read_text().splitlines() if line.startswith('{"benchmark_events"')]
                        if len(diagnostic) != 1:
                            raise RuntimeError("diagnostic event count missing")
                        row["consumed_events"] = diagnostic[0]["benchmark_events"]
                        expected = 0 if group == "P0" else row["final_metrics"]["events_attempted"] - row["final_metrics"]["ring_lost"]
                        if row["consumed_events"] != expected or not row["final_metrics"]["events_attempted"]:
                            raise RuntimeError("diagnostic stage did not process the expected events")
                        with (destination / f"round-{index+1}-{group}.jsonl").open() as stream:
                            if any(not json.loads(line)["event_type"].startswith("monitor_") for line in stream):
                                raise RuntimeError("diagnostic stage leaked normal event output")
                usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
                row["children_cpu_seconds"] = usage_after.ru_utime + usage_after.ru_stime - usage_before.ru_utime - usage_before.ru_stime
                # Includes workload children and collector startup/shutdown; not collector-only CPU.
                result["rounds"].append(row)
                (destination / "result.json").write_text(json.dumps(result, indent=2))
    result["median_seconds"] = {g: statistics.median(r["seconds"] for r in result["rounds"] if r["group"] == g) for g in groups}
    result["median_completion_seconds"] = {g: statistics.median(r["completion_seconds"] for r in result["rounds"] if r["group"] == g) for g in groups}
    completed_b0 = result["median_completion_seconds"]["B0"]
    result["completion_throughput_drop_percent"] = {g: 100*(1-completed_b0/v) for g, v in result["median_completion_seconds"].items() if g != "B0"}
    b0, b1 = result["median_seconds"]["B0"], result["median_seconds"]["B1"]
    result["stage_throughput_drop_percent"] = {g: 100*(1-b0/value) for g,value in result["median_seconds"].items() if g != "B0"}
    result["capture_loss_free"] = all(r.get("capture_loss_free", True) for r in result["rounds"])
    result["completed"] = True
    result["elapsed_increase_percent"] = 100*(b1/b0-1)
    result["throughput_drop_percent"] = 100*(1-b0/b1)
    if args.compare_records:
        full = result["median_seconds"]["B1-full"]
        result["compact_elapsed_reduction_percent"] = 100*(1-b1/full)
    (destination / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result["capture_loss_free"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
