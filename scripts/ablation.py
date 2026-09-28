"""Detection-only ablation on an existing real integration capture, not a speed benchmark."""
import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.model import load_config
from monitor.runtime import Pipeline
from monitor.storage import Store, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="integration evidence directory")
    parser.add_argument("--out", required=True, help="new results directory")
    args = parser.parse_args()
    source, destination = Path(args.input).resolve(), Path(args.out).resolve()
    original = json.loads((source / "result.json").read_text())
    if original.get("source") != "REAL_KERNEL_CAPTURE" or not original.get("passed"):
        parser.error("input must be a successful real integration capture")
    destination.mkdir(parents=True, exist_ok=False)
    config = load_config(source / "rules.json")
    raw = (source / "events.jsonl").read_bytes()
    records = [json.loads(line) for line in raw.splitlines() if line]
    # These names come from this project's controlled integration fixture only.
    worker = str(PurePosixPath(config["service_executables"][0]).parent / "worker")
    groups = {"single_event": ["R01", "R02", "R03"],
              "process_context": ["R01", "R02", "R03", "R04"],
              "sequence": ["R01", "R02", "R03", "R04", "C01", "C02"]}
    result = {"source": "REAL_CAPTURE_OFFLINE_DETECTION_ABLATION", "input_sha256": hashlib.sha256(raw).hexdigest(),
              "repetitions": original["repetitions"], "groups": {},
              "limitations": ["Same captured fixture in all groups; not independent attack families.",
                              "Disabled alerts do not remove engine computation; no CPU or speed claim.",
                              "Controlled examples do not estimate general precision or recall."]}
    for name, enabled in groups.items():
        store = Store(destination / f"{name}.db")
        try:
            pipeline = Pipeline({**config, "enabled": enabled}, store)
            for record in records:
                pipeline.push(record)
            pipeline.flush()
            alerts = store.alerts()
            selected = [a for a in alerts if a.get("exe") == worker]
            counts = dict(Counter(a["rule_id"] for a in selected))
            normal = sum(a.get("exe") in ("/usr/bin/cat", "/usr/bin/true") for a in alerts)
            result["groups"][name] = {"enabled": enabled, "worker_alert_counts": counts,
                "normal_fixture_alerts": normal, "passed": all(counts.get(rule, 0) == original["repetitions"] for rule in enabled)
                    and not (set(counts) - set(enabled)) and normal == 0,
                "correlated_evidence_lengths": sorted({len(a["evidence_ids"]) for a in selected if a["rule_id"].startswith("C")})}
            report(store, destination / f"{name}.html")
        finally:
            store.close()
    result["passed"] = all(group["passed"] for group in result["groups"].values())
    (destination / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
