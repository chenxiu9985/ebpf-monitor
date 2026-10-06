"""Local v4 functional acceptance with explicit full-plan gaps."""
import argparse
import json
import subprocess
import sys
import shutil
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.acceptance_storage import archive_results, check_storage, required_storage, save_result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--require-enforce",action="store_true")
    parser.add_argument("--stability-seconds",type=int,default=0)
    parser.add_argument("--stability-opens-per-second",type=int,default=1000)
    parser.add_argument("--native-data",action="store_true",help="run outputs on Linux temporary storage, then archive to --out")
    args=parser.parse_args(); out=args.out.resolve()
    if not 0<=args.stability_seconds<=86400: parser.error("invalid stability duration")
    if not 1<=args.stability_opens_per_second<=100000: parser.error("invalid stability rate")
    if args.native_data:
        if out.exists(): parser.error("choose a fresh output directory")
        out.parent.mkdir(parents=True,exist_ok=True)
        temporary = tempfile.mkdtemp(prefix="ebpf-v4-acceptance-")
        try:
            native=Path(temporary)/"acceptance"
            completed=subprocess.run([sys.executable,str(Path(__file__).resolve()),"--out",str(native),
                *(["--require-enforce"] if args.require_enforce else []),
                *(["--stability-seconds",str(args.stability_seconds),"--stability-opens-per-second",str(args.stability_opens_per_second)] if args.stability_seconds else [])],cwd=ROOT)
            method = archive_results(native,out) if native.exists() else "empty"
            if method == "empty": out.mkdir()
            (out/"execution-storage.json").write_text(json.dumps({"filesystem":subprocess.check_output(["stat","-f","-c","%T",temporary],text=True).strip(),
                "execution_directory":str(native),"archived_directory":str(out),"archive_method":method,"test_exit":completed.returncode},indent=2))
        except OSError as exc:
            print(f"Archival failed: {exc}. Evidence retained at {temporary}; inspect {out} for any moved or partially copied results.",flush=True)
            return 1
        else:
            shutil.rmtree(temporary)
        return completed.returncode
    out.mkdir(parents=True,exist_ok=False)
    result={"source":"V4_LOCAL_ACCEPTANCE", "checks":[], "local_functional_verified":False,
            "full_v4_plan_verified":False,"full_plan_gaps":["VMware target verification", "complete dynamic enforcement failure matrix",
                "representative business performance below 5%", "one-hour sustained input", "equivalent Falco/Tracee/Tetragon comparisons", "v4 detection/performance ablations", "kernel rule-related filtering"]}
    def run(name,command):
        with (out/(name+".log")).open("w") as log:
            completed=subprocess.run(command,cwd=ROOT,stdout=log,stderr=log)
        result["checks"].append({"name":name,"exit_code":completed.returncode,
                                 "status":"passed" if completed.returncode==0 else "unavailable" if completed.returncode==77 else "failed"})
    try:
        if args.stability_seconds:
            result["stability_storage_budget_bytes"] = required_storage(args.stability_seconds, args.stability_opens_per_second)
            check_storage(out, result["stability_storage_budget_bytes"])
        run("build",["bash",str(ROOT/"scripts/build.sh"),"-j2"])
        run("unit",[sys.executable,"-m","unittest","discover","-s","tests","-v"])
        run("shadow",[sys.executable,str(ROOT/"scripts/integration.py"),"--capture-mappings","--response-ready-fixture","--response-mode","shadow","--repetitions","3","--uid","1000","--out",str(out/"shadow")])
        for name,script in (("edges","live_edges.py"),("mapping","verify_mapping.py"),("shutdown_native","verify_shutdown_native.py"),("recovery","transport_recovery.py")):
            run(name,[sys.executable,str(ROOT/"scripts"/script),"--out",str(out/name)])
        run("equivalence",[sys.executable,str(ROOT/"scripts/equivalence.py"),str(out/"shadow/events.jsonl"),"--rules",str(out/"shadow/rules.json"),"--out",str(out/"equivalence.json")])
        run("enforce",[sys.executable,str(ROOT/"scripts/verify_response.py"),"--out",str(out/"enforce")])
        if args.stability_seconds:
            run("stability",[sys.executable,str(ROOT/"scripts/stability.py"),"--seconds",str(args.stability_seconds),"--opens-per-second",str(args.stability_opens_per_second),"--out",str(out/"stability")])
        core=[c for c in result["checks"] if c["name"]!="enforce"]
        result["local_functional_verified"]=all(c["status"]=="passed" for c in core)
        result["enforcement_verified"]=next(c["status"]=="passed" for c in result["checks"] if c["name"]=="enforce")
        return 0 if result["local_functional_verified"] and (not args.require_enforce or result["enforcement_verified"]) else 1
    except OSError as exc:
        result["error"] = str(exc)
        return 1
    finally:
        saved = save_result(out/"acceptance.json", result)
        print(json.dumps(result,indent=2))
        if not saved: return 1


if __name__=="__main__": raise SystemExit(main())
