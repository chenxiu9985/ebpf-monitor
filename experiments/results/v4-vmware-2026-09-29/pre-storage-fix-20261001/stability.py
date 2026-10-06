"""Bounded live sustained-input acceptance; default 1 hour, never an idle uptime claim."""
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

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from monitor.runtime import doctor
from scripts.integration import stop,wait_for


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",required=True,type=Path)
    parser.add_argument("--seconds",type=int,default=3600)
    parser.add_argument("--opens-per-second",type=int,default=1000)
    args=parser.parse_args()
    if not 1<=args.seconds<=86400 or not 1<=args.opens_per_second<=100000: parser.error("invalid workload bounds")
    out=args.out.resolve(); out.mkdir(parents=True,exist_ok=False)
    result={"source":"REAL_SUSTAINED_INPUT", "environment":doctor(),"seconds_requested":args.seconds,
            "rate_requested":args.opens_per_second,"generated":0,"samples":[],"passed":False}
    process=None
    try:
        with tempfile.TemporaryDirectory(prefix="ebpf-v4-stability-") as directory:
            fixture=Path(directory)/"fixture"; fixture.write_text("harmless stability data")
            with (out/"supervisor.log").open("w") as log:
                process=subprocess.Popen([sys.executable,str(ROOT/"scripts/run_live.py"),"--out",str(out/"session")],cwd=ROOT,stdout=log,stderr=log)
                wait_for(lambda:(out/"session/collector.log").exists() and '"event_type":"monitor_start"' in (out/"session/collector.log").read_text(),process)
                ids=None
                for line in (out/"supervisor.log").read_text().splitlines():
                    try:
                        row=json.loads(line)
                        if "collector_pid" in row: ids=row
                    except ValueError: pass
                start=time.monotonic(); next_sample=start
                batch=max(1,args.opens_per_second//100)
                while time.monotonic()-start<args.seconds:
                    if process.poll() is not None: raise RuntimeError("monitor exited during workload")
                    for _ in range(batch):
                        fd=os.open(fixture,os.O_RDONLY); os.close(fd); result["generated"]+=1
                    now=time.monotonic()
                    if now>=next_sample:
                        sample={"elapsed_seconds":now-start,"generated":result["generated"]}
                        if ids:
                            sample["rss_kib"]={name:next(int(s.split()[1]) for s in Path(f"/proc/{pid}/status").read_text().splitlines() if s.startswith("VmRSS:")) for name,pid in ids.items()}
                        result["samples"].append(sample); next_sample=now+1
                    target=start+result["generated"]/args.opens_per_second
                    if target>now: time.sleep(min(target-now,0.02))
                result["workload_seconds"]=time.monotonic()-start
                process.send_signal(signal.SIGINT); process.wait(timeout=20)
            session=json.loads((out/"session/session.json").read_text())
            with sqlite3.connect(out/"session/alerts.db") as db:
                saved=db.execute("SELECT COUNT(*) FROM events WHERE json_extract(body,'$.event_type')='file_open' AND json_extract(body,'$.path')=?",(str(fixture),)).fetchone()[0]
            result.update(saved=saved,session=session,rate_achieved=result["generated"]/result["workload_seconds"],
                          passed=process.returncode==0 and session["capture_loss_free"] and saved==result["generated"])
        return 0 if result["passed"] else 1
    except (OSError,RuntimeError,subprocess.SubprocessError) as exc:
        result["error"]=str(exc); return 1
    finally:
        stop(process)
        (out/"result.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
        print(json.dumps({"passed":result["passed"],"generated":result["generated"],"saved":result.get("saved"),"seconds":result.get("workload_seconds")}))


if __name__=="__main__": raise SystemExit(main())
