"""Freeze implemented source/build/dependencies and verify the retained v3 baseline."""
import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from monitor.runtime import doctor


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    files={str(f.relative_to(ROOT)):sha(f) for name in ("bpf","collector","monitor","scripts","tests","schema","rules","config")
           for f in sorted((ROOT/name).rglob("*")) if f.is_file() and "__pycache__" not in f.parts}
    for name in ("Makefile","requirements.txt","README.md"):
        files[name]=sha(ROOT/name)
    baseline=json.loads((ROOT/"docs/V3_BASELINE_SHA256.json").read_text(encoding="utf-8-sig"))
    changed=[]
    for row in baseline["records"]:
        path=ROOT.parent/"ebpf-monitor-v3"/row["path"]
        if not path.is_file() or sha(path)!=row["sha256"]: changed.append(row["path"])
    versions={"python":sys.version}
    try:
        import yaml
        versions["PyYAML"]=yaml.__version__
    except ImportError: versions["PyYAML"]=None
    for tool in ("clang","cc","pkg-config"):
        try: versions[tool]=subprocess.check_output([tool,"--version"],text=True,stderr=subprocess.STDOUT).splitlines()[0]
        except (OSError,subprocess.SubprocessError) as exc: versions[tool]=str(exc)
    try: versions["libbpf"]=subprocess.check_output(["pkg-config","--modversion","libbpf"],text=True).strip()
    except (OSError,subprocess.SubprocessError): versions["libbpf"]=None
    result={"source_sha256":files,"source_tree_sha256":hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest(),
            "build_sha256":{str(f.relative_to(ROOT)):sha(f) for f in sorted((ROOT/"build").glob("*")) if f.is_file() and not f.name.endswith(".tmp")},
            "environment":doctor(),"platform":platform.platform(),"versions":versions,
            "baseline_retained_unchanged":not changed,"baseline_changed_files":changed}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({"source_tree_sha256":result["source_tree_sha256"],"baseline_retained_unchanged":not changed,"versions":versions}))
    return 0 if not changed else 1


if __name__=="__main__": raise SystemExit(main())
