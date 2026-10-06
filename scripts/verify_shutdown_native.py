"""Run the unchanged shutdown matrix on Linux local temporary storage; archive results."""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",required=True,type=Path)
    args=parser.parse_args(); out=args.out.resolve()
    if out.exists(): parser.error("choose a fresh output directory")
    out.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ebpf-v4-native-") as temporary:
        native=Path(temporary)/"shutdown"
        filesystem=subprocess.check_output(["stat","-f","-c","%T",temporary],text=True).strip()
        completed=subprocess.run([sys.executable,str(ROOT/"scripts/verify_shutdown.py"),"--out",str(native)],cwd=ROOT)
        if native.exists(): shutil.copytree(native,out)
        else: out.mkdir()
        (out/"execution-storage.json").write_text(json.dumps({"filesystem":filesystem,"execution_directory":str(native),
            "archived_directory":str(out),"test_exit":completed.returncode,"note":"Unchanged 10000-open, 5000-ms matrix; native outputs archived after completion."},indent=2))
    return completed.returncode


if __name__=="__main__": raise SystemExit(main())
