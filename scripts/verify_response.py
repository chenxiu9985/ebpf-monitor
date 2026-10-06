"""Real dynamic LSM acceptance; exit 77 is unavailable, never success."""
import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from monitor.model import load_config
from monitor.runtime import doctor
from scripts.integration import stop, wait_for


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--uid",type=int,default=1000)
    args=parser.parse_args()
    out=args.out.resolve(); out.mkdir(parents=True,exist_ok=False)
    result={"source":"REAL_DYNAMIC_RESPONSE_ACCEPTANCE", "environment":doctor(),"status":"not_run","passed":False,"rounds":[]}
    group=Path("/sys/fs/cgroup")/f"ebpf-v4-response-{os.getpid()}"
    analyzer=collector=None; created=False
    try:
        if os.geteuid()!=0 or result["environment"]["bpf_lsm_active"] is not True:
            result.update(status="unavailable",reason="Root and confirmed active BPF LSM required; kernel configuration was not modified.")
            return 77
        group.mkdir(); created=True
        with tempfile.TemporaryDirectory(prefix="ebpf-v4-response-") as directory:
            temp=Path(directory); temp.chmod(0o755)
            obj,service,worker=temp/"protected",temp/"service",temp/"worker"
            obj.write_text("harmless data"); obj.chmod(0o644)
            for source,binary in (("response_service.c",service),("response_worker.c",worker)):
                subprocess.run(["cc","-Wall","-Wextra","-Werror",str(ROOT/"tests/fixtures"/source),"-o",str(binary)],check=True)
            rules=out/"rules.json"
            rules.write_text(json.dumps({**load_config(),"service_executables":[str(service)],"sensitive_paths":[str(obj)],"response_mode":"enforce","response_scope":"legacy","response_ttl_ms":3000}))
            def identity():
                (group/"cgroup.procs").write_text(str(os.getpid()))
                os.setgroups([]); os.setgid(args.uid); os.setuid(args.uid)
            baseline=subprocess.run([str(worker),str(obj)],env={"PATH":"/usr/bin:/bin"},preexec_fn=identity,capture_output=True,text=True,check=True)
            initial=[json.loads(s) for s in baseline.stdout.splitlines()]
            if not all(r["retval"]>=0 for r in initial): raise RuntimeError("baseline opens failed")
            result["baseline"]=initial
            sock,control=temp/"events.sock",temp/"control.sock"
            with (out/"analyzer.log").open("w") as alog,(out/"collector.log").open("w") as clog:
                analyzer=subprocess.Popen([sys.executable,"-m","monitor","listen","--socket",str(sock),"--control-socket",str(control),
                    "--db",str(out/"alerts.db"),"--raw",str(out/"events.jsonl"),"--rules",str(rules),"--exit-on-stop"],cwd=ROOT,stdout=alog,stderr=alog)
                wait_for(sock.exists,analyzer)
                collector=subprocess.Popen([str(ROOT/"build/collector"),"--socket",str(sock),"--exclude-pid",str(analyzer.pid),
                    "--control-socket",str(control),"--control-object",str(obj),"--control-cgroup",str(group),"--control-target-uid",str(args.uid)],cwd=ROOT,stdout=clog,stderr=clog)
                wait_for(lambda: '"event_type":"monitor_start"' in (out/"collector.log").read_text(),collector)
                used_requests=set()
                for gap in (0,1000,10000):
                    ready=temp/f"ready-{gap}"
                    worklog=out/f"worker-{gap}.jsonl"
                    with worklog.open("w") as log:
                        child=subprocess.Popen([str(service),str(worker),str(obj)],preexec_fn=identity,
                            env={"PATH":"/usr/bin:/bin","EBPF_GAP_US":str(gap),"EBPF_READY_FILE":str(ready)},stdout=log,text=True)
                        try:
                            applied=None
                            until=time.monotonic()+7
                            while time.monotonic()<until:
                                with sqlite3.connect(out/"alerts.db") as db:
                                    rows=[json.loads(r[0]) for r in db.execute("SELECT body FROM responses WHERE state='applied'")]
                                unique={r["request_id"]:r for r in rows}
                                applied=next((r for rid,r in unique.items() if rid not in used_requests),None)
                                if applied:
                                    used_requests.add(applied["request_id"]); break
                                if child.poll() is not None: raise RuntimeError("worker exited before application confirmation")
                                time.sleep(0.02)
                            if not applied: raise RuntimeError("no applied policy; inspect quality and control timeline")
                            ready.write_text("confirmed")
                            child.wait(timeout=7)
                            if child.returncode: raise RuntimeError("response worker failed")
                        finally:
                            stop(child)
                    operations=[json.loads(s) for s in worklog.read_text().splitlines()]
                    before=[r for r in operations if r["phase"]=="initial"]
                    after=[r for r in operations if r["phase"]=="after_confirmation"]
                    expired=[r for r in operations if r["phase"]=="after_expiry"]
                    preserved=next(r["retval"] for r in operations if r["phase"]=="existing_fd_read")
                    matched=all(r["retval"]==-1 and r["errno"]==1 and r["before_ns"]>applied["update_after_ns"] for r in after)
                    passed=matched and all(r["retval"]>=0 for r in expired) and preserved==1
                    result["rounds"].append({"gap_us":gap,"operations":operations,"policy":applied,
                        "first_open_denied":before[0]["retval"]<0,"initial_escaped":sum(r["retval"]>=0 for r in before),
                        "post_confirm_matched":matched,"passed":passed})
                normal=subprocess.run([str(worker),str(obj)],preexec_fn=identity,env={"PATH":"/usr/bin:/bin"},capture_output=True,text=True,check=True)
                result["nonmatching_opens"]=all(json.loads(s)["retval"]>=0 for s in normal.stdout.splitlines())
                stop(collector); analyzer.wait(timeout=5)
                result.update(status="executed",passed=all(r["passed"] for r in result["rounds"]) and result["nonmatching_opens"] and collector.returncode==0 and analyzer.returncode==0)
        return 0 if result["passed"] else 1
    except (OSError,RuntimeError,subprocess.SubprocessError) as exc:
        result.update(status="failed",reason=str(exc)); return 1
    finally:
        stop(collector); stop(analyzer)
        if created:
            try: group.rmdir()
            except OSError as exc: result["cleanup_error"]=str(exc)
        (out/"result.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
        print(json.dumps(result,indent=2))


if __name__=="__main__": raise SystemExit(main())
