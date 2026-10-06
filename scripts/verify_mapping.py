"""Real kernel file-mapping pairing, links, FD reuse and multithread checks."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from monitor.runtime import doctor
from scripts.integration import stop,wait_for


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--uid",type=int,default=1000)
    args=parser.parse_args(); out=args.out.resolve(); out.mkdir(parents=True,exist_ok=False)
    result={"source":"REAL_MAPPING_EDGE_TEST", "environment":doctor(),"passed":False,"checks":{}}
    collector=None
    try:
        with tempfile.TemporaryDirectory(prefix="ebpf-v4-mapping-") as directory:
            temp=Path(directory); temp.chmod(0o755)
            library,binary,other=temp/"benign.so",temp/"mapping",temp/"other"
            other.write_bytes(b"x"*4096); other.chmod(0o644)
            subprocess.run(["cc","-shared","-fPIC",str(ROOT/"tests/fixtures/benign_preload.c"),"-o",str(library)],check=True)
            subprocess.run(["cc","-Wall","-Wextra","-Werror","-pthread",str(ROOT/"tests/fixtures/mapping_edges.c"),"-o",str(binary)],check=True)
            hard,symbol=temp/"hardlink",temp/"symlink"; os.link(library,hard); symbol.symlink_to(library)
            with (out/"events.jsonl").open("w") as raw,(out/"collector.log").open("w") as log:
                collector=subprocess.Popen([str(ROOT/"build/collector"),"--capture-mappings"],stdout=raw,stderr=log)
                wait_for(lambda:'"event_type":"monitor_start"' in (out/"collector.log").read_text(),collector)
                def identity():
                    if os.geteuid()==0: os.setgroups([]); os.setgid(args.uid); os.setuid(args.uid)
                fixture=subprocess.run([str(binary),str(library),str(hard),str(symbol),str(other)],
                    preexec_fn=identity,env={"PATH":"/usr/bin:/bin","LD_PRELOAD":str(library)},capture_output=True,text=True,timeout=5)
                result["fixture_returncode"]=fixture.returncode
                result["fixture_output"]=fixture.stdout
                stop(collector)
            events=[json.loads(s) for s in (out/"events.jsonl").read_text().splitlines()]
            execution=next(e for e in events if e["event_type"]=="process_exec" and e.get("exe")==str(binary))
            records=[e for e in events if e.get("process_key")==execution["process_key"] and e.get("exec_token")==execution["exec_token"]]
            mappings=[e for e in records if e["event_type"]=="file_mapping"]
            inode=library.stat().st_ino; other_inode=other.stat().st_ino
            result["checks"]={"fixture_succeeded":fixture.returncode==0,
                "successful_object_result":any(e["inode"]==inode and e["result_state"]=="succeeded" for e in mappings),
                "failed_mmap_result":any(e["result_state"]=="failed" for e in mappings),
                "fd_reuse_different_object":any(e["inode"]==other_inode and e["result_state"]=="succeeded" for e in mappings),
                "thread_mapping_same_exec_token":any(e["inode"]==inode and e["tid"]!=e["tgid"] and e["exec_token"]==execution["exec_token"] for e in mappings),
                "link_object_identity":all(any(e["event_type"]=="file_open" and e.get("path")==str(p) and e["inode"]==inode for e in records) for p in (hard,symbol)),
                "collector_normal_exit":collector.returncode==0}
            result["mapping_records"]=mappings
            result["final_metrics"]=next(e["metrics"] for e in reversed(events) if e["event_type"]=="monitor_stop")
            result["checks"]["loss_free"]=all(result["final_metrics"].get(k)==0 for k in ("ring_lost","map_fail","queue_lost","unpaired"))
            result["passed"]=all(result["checks"].values())
        return 0 if result["passed"] else 1
    except (OSError,RuntimeError,StopIteration,subprocess.SubprocessError) as exc:
        result["error"]=str(exc); return 1
    finally:
        stop(collector)
        (out/"result.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
        print(json.dumps({"passed":result["passed"],"checks":result["checks"]}))


if __name__=="__main__": raise SystemExit(main())
