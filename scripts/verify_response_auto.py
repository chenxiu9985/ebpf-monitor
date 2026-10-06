"""Real automatic response acceptance; workloads never wait for policy application."""
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
from monitor.assets import write_manifest
from monitor.model import load_config
from monitor.runtime import doctor
from scripts.integration import stop, wait_for


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--uid",type=int,default=1000,help="second fixture identity; never passed to collector")
    args=parser.parse_args()
    if not 0<=args.uid<2**32: raise ValueError("invalid fixture UID")
    out=args.out.resolve(); out.mkdir(parents=True,exist_ok=False)
    result=dict(source="REAL_AUTOMATIC_RESPONSE_ACCEPTANCE",environment=doctor(),status="not_run",passed=False,
                first_open_guaranteed=False,workload_waits_for_policy=False,rounds=[])
    analyzer=collector=None; services=[]
    try:
        if os.geteuid()!=0 or result["environment"]["bpf_lsm_active"] is not True:
            result.update(status="unavailable",reason="Root and active BPF LSM required; no kernel configuration changed")
            return 77
        with tempfile.TemporaryDirectory(prefix="ebpf-v4-auto-") as directory:
            temp=Path(directory); temp.chmod(0o755)
            obj,second,service,worker=temp/"protected-a",temp/"protected-b",temp/"service",temp/"worker"
            for path in (obj,second): path.write_text("harmless data\n"); path.chmod(0o644)
            for name,binary in (("auto_response_service.c",service),("auto_response_worker.c",worker)):
                subprocess.run(["cc","-O2","-Wall","-Wextra","-Werror",str(ROOT/"tests/fixtures"/name),"-o",str(binary)],check=True)
            rules=out/"rules.json"
            config={**load_config(),"service_executables":[str(service)],"sensitive_paths":[str(obj),str(second)],
                    "response_mode":"enforce","response_scope":"auto","response_ttl_ms":3000}
            rules.write_text(json.dumps(config,indent=2))
            manifest=out/"response-assets.tsv"; write_manifest(config,manifest)
            cases=[("existing-root",0,5500),("existing-user-helper",args.uid,5500),("short-lived",args.uid,0)]
            # All services start BEFORE hook attachment. Only workload start is gated.
            for name,uid,duration in cases:
                def identity(uid=uid):
                    os.setgroups([]); os.setgid(uid); os.setuid(uid)
                trigger=temp/(name+".start")
                log=(out/(name+".jsonl")).open("w")
                env={"PATH":"/usr/bin:/bin","EBPF_START_FILE":str(trigger)}
                if "helper" in name: env["EBPF_HELPER"]="1"
                child=subprocess.Popen([str(service),str(worker),str(obj),str(second),str(duration)],
                                       env=env,preexec_fn=identity,stdout=log,start_new_session=True)
                services.append((child,log,trigger,name,uid,duration))
            for child,*_ in services:
                wait_for(lambda child=child: Path(f"/proc/{child.pid}/exe").resolve()==service,child)
            sock,control=temp/"events.sock",temp/"control.sock"
            with (out/"analyzer.log").open("w") as alog,(out/"collector.log").open("w") as clog:
                analyzer=subprocess.Popen([sys.executable,"-m","monitor","listen","--socket",str(sock),
                    "--control-socket",str(control),"--db",str(out/"alerts.db"),"--raw",str(out/"events.jsonl"),
                    "--alerts",str(out/"alerts.jsonl"),"--rules",str(rules),"--exit-on-stop"],cwd=ROOT,stdout=alog,stderr=alog)
                wait_for(sock.exists,analyzer)
                collector=subprocess.Popen([str(ROOT/"build/collector"),"--socket",str(sock),"--exclude-pid",str(analyzer.pid),
                    "--control-socket",str(control),"--control-manifest",str(manifest)],cwd=ROOT,stdout=clog,stderr=clog)
                wait_for(lambda: '"event_type":"monitor_start"' in (out/"collector.log").read_text(),collector)
                for child,log,trigger,name,uid,duration in services:
                    trigger.touch()  # no policy polling, acknowledgement, or READY file
                    if duration:
                        time.sleep(1.5)
                        replacement=temp/(name+".replacement")
                        replacement.write_text("replacement harmless data\n"); replacement.chmod(0o644)
                        replacement.replace(second)
                        result.setdefault("replacements",{})[name]=dict(inode=second.stat().st_ino,time_ns=time.monotonic_ns())
                    child.wait(timeout=duration/1000+5); log.close()
                    if child.returncode: raise RuntimeError(f"{name}: worker failed")
                time.sleep(1.2)  # let the reorder buffer drain after short-lived worker exit
                baseline=subprocess.run([str(worker),str(obj),str(second),"0"],env={"PATH":"/usr/bin:/bin"},capture_output=True,text=True,check=True)
                result["nonmatching_opens"]=all(json.loads(s)["retval"]>=0 for s in baseline.stdout.splitlines() if json.loads(s)["phase"]=="open")
                stop(collector); analyzer.wait(timeout=5)
                if collector.returncode or analyzer.returncode: raise RuntimeError("collector/analyzer shutdown failed")
            with sqlite3.connect(out/"alerts.db") as db:
                responses=[json.loads(r[0]) for r in db.execute("SELECT body FROM responses")]
            events=[json.loads(s) for s in (out/"events.jsonl").read_text().splitlines()]
            for _,_,_,name,uid,duration in services:
                rows=[json.loads(s) for s in (out/(name+".jsonl")).read_text().splitlines()]
                opens=[r for r in rows if r["phase"]=="open"]; pid=opens[0]["tgid"]
                applied=next((r for r in responses if r["state"]=="applied" and
                              (r.get("tgid") or r.get("request",{}).get("tgid"))==pid),None)
                round_=dict(name=name,uid=uid,tgid=pid,first_open_denied=opens[0]["retval"]<0,policy=applied)
                if duration and applied:
                    replacement=result["replacements"][name]
                    refreshed=next((e["monotonic_ns"] for e in events if e["event_type"]=="monitor_registry" and
                        any(o.get("active") and o.get("inode")==replacement["inode"] for o in e.get("objects",[]))),None)
                    in_refresh_gap=lambda r: r["object"]==2 and r["after_ns"]>=replacement["time_ns"] and (refreshed is None or r["before_ns"]<refreshed)
                    active=[r for r in opens if not in_refresh_gap(r) and r["before_ns"]>=applied["update_after_ns"] and r["after_ns"]<applied["expires_ns"]]
                    after=[r for r in opens if r["before_ns"]>applied["expires_ns"]]
                    denied_objects={r["object"] for r in active if r["retval"]==-1 and r["errno"]==1}
                    replaced_denied=any(e.get("dynamic_policy_id")==applied["policy_id"] and
                        e.get("inode")==replacement["inode"] and e.get("tgid")==pid for e in events if e["event_type"]=="policy_denied")
                    round_.update(initial_escaped=sum(r["retval"]>=0 and r["before_ns"]<applied["update_after_ns"] for r in opens),
                                  denied_objects=sorted(denied_objects),replacement_denied=replaced_denied,
                                  registry_refresh_ns=refreshed,
                                  refresh_gap_escaped=sum(r["retval"]>=0 and in_refresh_gap(r) for r in opens),
                                  recovered=bool(after) and all(r["retval"]>=0 for r in after),
                                  existing_fd_read=rows[-1]["retval"],
                                  passed=denied_objects=={1,2} and bool(active) and all(r["retval"]==-1 and r["errno"]==1 for r in active)
                                      and bool(after) and all(r["retval"]>=0 for r in after) and replaced_denied and rows[-1]["retval"]==1)
                elif duration:
                    round_.update(passed=False,reason="no applied policy")
                else:
                    round_.update(escaped=sum(r["retval"]>=0 for r in opens),passed=None,measurement_complete=True,
                                  outcome="reported; short-lived interception is not guaranteed")
                result["rounds"].append(round_)
            metrics=next((e["metrics"] for e in reversed(events) if "metrics" in e),{})
            result["final_metrics"]=metrics
            result["capture_loss_free"]=all(metrics.get(k)==0 for k in ("ring_lost","map_fail","unpaired","queue_lost","transport_disconnects"))
            result.update(status="executed",passed=all(r["passed"] is True for r in result["rounds"] if r["name"]!="short-lived") and
                          all(r.get("measurement_complete") is True for r in result["rounds"] if r["name"]=="short-lived") and result["nonmatching_opens"] and result["capture_loss_free"])
            return 0 if result["passed"] else 1
    except (OSError,RuntimeError,ValueError,subprocess.SubprocessError) as exc:
        result.update(status="failed",reason=str(exc)); return 1
    finally:
        stop(collector); stop(analyzer)
        for child,log,*_ in services:
            if child.poll() is None:
                try: os.killpg(child.pid,15)
                except ProcessLookupError: pass
            stop(child); log.close()
        (out/"result.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
        print(json.dumps(result,indent=2))


if __name__=="__main__": raise SystemExit(main())
