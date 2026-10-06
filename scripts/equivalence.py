"""Compare alerts/evidence/quality from identical input, full vs storage-filtered."""
import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.model import load_config
from monitor.runtime import Pipeline
from monitor.storage import Store


def run(records, config, directory, profile):
    store = Store(directory/(profile+".db"))
    try:
        pipeline = Pipeline({**config, "capture_profile": profile}, store)
        for e in records: pipeline.push(e)
        pipeline.flush()
        alerts = store.alerts()
        for a in alerts: a.pop("storage_submit_ns", None)
        return {"alerts": alerts, "filtered": pipeline.capture.filtered,
                "considered": pipeline.capture.considered,
                "saved": store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]}
    finally:
        store.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--rules")
    parser.add_argument("--out", required=True, type=Path)
    args=parser.parse_args()
    records=[json.loads(line) for line in args.input.read_text().splitlines() if line]
    with tempfile.TemporaryDirectory() as tmp:
        full=run(records,load_config(args.rules),Path(tmp),"full")
        filtered=run(records,load_config(args.rules),Path(tmp),"rule_related")
    result={"source":"SAME_INPUT_STORAGE_EQUIVALENCE", "passed":full["alerts"]==filtered["alerts"],
            "input":str(args.input), "full":full, "rule_related":filtered,
            "scope":"Storage/analysis savings only; kernel/ring/collector/transport remain unchanged."}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({"passed":result["passed"],"saved_full":full["saved"],"saved_filtered":filtered["saved"]}))
    return 0 if result["passed"] else 1


if __name__=="__main__": raise SystemExit(main())
