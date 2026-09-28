"""Sequential local/target acceptance with explicit incomplete and failed stages."""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="new evidence directory")
    parser.add_argument("--uid", type=int, default=1000)
    parser.add_argument("--repetitions", type=int, default=30)
    args = parser.parse_args()
    if platform.system() != "Linux" or os.geteuid() != 0:
        parser.error("run on Linux using sudo; kernel capture requires privileges")
    if args.uid <= 0 or args.repetitions < 1:
        parser.error("use a non-root workload UID and positive repetition count")
    destination = Path(args.out).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    manifest = {}
    for directory in ("bpf", "collector", "monitor", "scripts", "tests", "rules", "schema", "config"):
        for file in sorted((ROOT / directory).rglob("*")):
            if file.is_file() and "__pycache__" not in file.parts:
                manifest[file.relative_to(ROOT).as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
    result = {"started_utc": datetime.now(timezone.utc).isoformat(), "kernel": platform.release(),
              "source_sha256": manifest, "stages": [], "scope": "self-project acceptance; competitors and one-hour workload excluded"}
    python = sys.executable
    stages = [
        ("environment", ["bash", "scripts/target_check.sh"], False),
        ("build", ["bash", "scripts/build.sh"], True),
        ("unit", [python, "-m", "unittest", "discover", "-s", "tests", "-v"], True),
        ("integration", [python, "scripts/integration.py", "--out", str(destination / "integration"),
                         "--repetitions", str(args.repetitions), "--uid", str(args.uid)], False),
        ("edges", [python, "scripts/live_edges.py", "--out", str(destination / "edges")], False),
        ("recovery", [python, "scripts/transport_recovery.py", "--out", str(destination / "recovery")], False),
        ("benchmark", [python, "scripts/benchmark.py", "--out", str(destination / "benchmark"), "--rounds", "5"], False),
        ("lsm", [python, "scripts/verify_lsm.py", "--out", str(destination / "lsm"), "--uid", str(args.uid)], False),
    ]
    def save():
        (destination / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    save()
    for name, command, fatal in stages:
        print(f"Running {name}", flush=True)
        with (destination / f"{name}.log").open("w", encoding="utf-8") as log:
            run = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        status = "passed" if run.returncode == 0 else "unavailable" if name == "lsm" and run.returncode == 77 else "failed"
        result["stages"].append({"name": name, "status": status, "returncode": run.returncode})
        save()
        if fatal and run.returncode:
            break
    result["performance_targets"] = {}
    for stage, field, limit in (("integration", "delivery_delay_ms", 500), ("benchmark", "throughput_drop_percent", 5)):
        file = destination / stage / "result.json"
        if file.exists():
            data = json.loads(file.read_text())
            value = data.get(field)
            if stage == "integration" and isinstance(value, dict):
                value = value.get("p95")
            if isinstance(value, (float, int)):
                result["performance_targets"][stage] = {"measured": value, "strict_upper_limit": limit, "passed": value < limit}
    result["suite_passed"] = (len(result["stages"]) == len(stages)
        and all(s["status"] == "passed" for s in result["stages"])
        and len(result["performance_targets"]) == 2
        and all(t["passed"] for t in result["performance_targets"].values()))
    result["finished_utc"] = datetime.now(timezone.utc).isoformat()
    save()
    print(json.dumps({"summary": str(destination / "summary.json"), "suite_passed": result["suite_passed"]}))
    return 0 if result["suite_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
