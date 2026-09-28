"""Synthetic fixtures are analyzer tests, never reported as real kernel capture."""
import json
from pathlib import Path

from .model import load_config
from .runtime import Pipeline
from .storage import Store, report


def event(index, kind, key="worker:1", parent="", **fields):
    return {"schema_version": 1, "event_id": f"synthetic:{index}", "event_type": kind,
            "monotonic_ns": index*1_000_000_000, "process_key": key,
            "parent_process_key": parent, "uid": 1000, "euid": 1000,
            "result_state": "succeeded", "quality_flags": 0, **fields}


def malicious_chain():
    return [event(1, "process_exec", "service:1", exe="/usr/bin/demo-service"),
            event(2, "process_fork", "shell:1", "service:1"),
            event(3, "process_exec", "shell:1", "service:1", exe="/bin/bash"),
            event(4, "process_fork", "worker:1", "shell:1"),
            event(5, "process_exec", "worker:1", "shell:1", exe="/tmp/demo-worker", env={"LD_PRELOAD": "/tmp/demo.so"}),
            event(6, "file_open", path="/etc/shadow", retval=-13, result_state="failed"),
            event(7, "ptrace", request=5, target_pid=999, retval=-1, result_state="failed")]


def demo(destination):
    directory = Path(destination)
    directory.mkdir(parents=True, exist_ok=True)
    records = malicious_chain()
    raw = directory / "synthetic-events.jsonl"
    raw.write_text("".join(json.dumps(e) + "\n" for e in records), encoding="utf-8")
    store = Store(directory / "alerts.db")
    try:
        pipeline = Pipeline(load_config(), store, alerts=directory / "alerts.jsonl")
        for e in records:
            pipeline.push(e)
        pipeline.flush()
        report(store, directory / "report.html")
        print(json.dumps({"source": "SYNTHETIC_ANALYZER_TEST", "alerts": len(store.alerts()), "out": str(directory)}))
    finally:
        store.close()
