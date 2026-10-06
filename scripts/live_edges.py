"""Kernel regression fixtures: no exploit, only owned processes and temporary files."""
import argparse
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.runtime import doctor


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="out/edges")
    args = p.parse_args()
    output = Path(args.out).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "events.jsonl").exists():
        raise RuntimeError("use a new output directory")
    result = {"source": "REAL_KERNEL_EDGE_TESTS", "environment": doctor(), "checks": {}}
    with tempfile.TemporaryDirectory(prefix="ebpf-edges-") as directory:
        temp = Path(directory)
        binary = temp / "edges"
        subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", "-pthread", str(ROOT / "tests/fixtures/edges.c"), "-o", str(binary)], check=True)
        file = temp / "original"
        file.write_text("harmless data\n")
        alias = temp / "hardlink"
        os.link(file, alias)
        with (output / "events.jsonl").open("w") as raw, (output / "collector.log").open("w") as log:
            collector = subprocess.Popen([str(ROOT / "build/collector")], stdout=raw, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while '"event_type":"monitor_start"' not in (output / "collector.log").read_text():
                    if collector.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("collector failed to start")
                    time.sleep(0.05)
                pids, paths = {}, {}
                for mode in ("openat2", "execveat", "thread-exec", "exec-fail", "ptrace"):
                    specific = temp / f"edges-{mode}"
                    shutil.copyfile(binary, specific)
                    specific.chmod(0o755)
                    paths[mode] = str(specific)
                    process = subprocess.Popen([str(specific), mode] + ([str(alias)] if mode == "openat2" else []))
                    pids[mode] = process.pid
                    if process.wait(timeout=5):
                        raise RuntimeError(f"fixture failed: {mode}")
                symbolic = temp / "symlink"
                symbolic.symlink_to(file)
                fd = os.open(symbolic, os.O_RDONLY)
                os.close(fd)
                directory_fd = os.open(temp, os.O_RDONLY | os.O_DIRECTORY)
                fd = os.open("hardlink", os.O_RDONLY, dir_fd=directory_fd)
                os.close(fd)
                os.close(directory_fd)
                unicode_path = temp / "测试-文件"
                unicode_path.write_text("utf8 fixture\n")
                fd = os.open(unicode_path, os.O_RDONLY)
                os.close(fd)
                preload_config = temp / "ld.so.preload"
                preload_config.write_text("harmless fixture\n")
                replacement = temp / "replacement"
                replacement.write_text("replacement\n")
                replacement.replace(preload_config)
                preload_config.unlink()
                padded_env = {f"PAD{i:03d}": "x" for i in range(70)}
                padded_env["LD_PRELOAD"] = "/nonexistent/ebpf-fixture.so"
                subprocess.run(["/usr/bin/true"], env=padded_env, stderr=subprocess.DEVNULL, check=True)
            finally:
                collector.send_signal(signal.SIGTERM)
                collector.wait(timeout=5)
        rows = [json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()]
        namespace_pids = dict(pids)
        for mode, path in paths.items():
            match = next((e for e in rows if e["event_type"] == "process_exec" and e.get("exe") == path), None)
            pids[mode] = match["tgid"] if match else None
        result["pid_mapping"] = {mode: {"namespace_pid": namespace_pids[mode], "host_pid": pids[mode]} for mode in pids}
        def events(mode, kind):
            return [e for e in rows if e.get("tgid") == pids[mode] and e["event_type"] == kind]
        opens = [e for e in events("openat2", "file_open") if e.get("path") == str(alias)]
        result["checks"]["openat2_hardlink_identity"] = bool(opens and opens[0]["inode"] == file.stat().st_ino and opens[0]["retval"] >= 0)
        result["checks"]["symlink_identity"] = any(e["event_type"] == "file_open" and e.get("path") == str(symbolic) and e.get("inode") == file.stat().st_ino for e in rows)
        result["checks"]["relative_dirfd_identity"] = any(e["event_type"] == "file_open" and e.get("path") == "hardlink" and e.get("inode") == file.stat().st_ino for e in rows)
        result["checks"]["utf8_path_roundtrip"] = any(e["event_type"] == "file_open" and e.get("path") == str(unicode_path) for e in rows)
        result["checks"]["preload_config_rename"] = any(e["event_type"] == "file_rename" and e.get("path2") == str(preload_config) and e.get("retval") == 0 for e in rows)
        result["checks"]["preload_config_unlink"] = any(e["event_type"] == "file_unlink" and e.get("path") == str(preload_config) and e.get("retval") == 0 for e in rows)
        result["checks"]["environment_limit_visible"] = any(e["event_type"] == "process_exec" and e.get("exe") == "/usr/bin/true" and e.get("quality_flags", 0) & 8 and not e.get("env", {}).get("LD_PRELOAD") for e in rows)
        for mode in ("execveat", "thread-exec"):
            execs = events(mode, "process_exec")
            result["checks"][mode] = len(execs) == 2 and not bool(execs[-1]["quality_flags"] & 4)
            result["checks"][mode+"_kernel_exec_token"] = len(execs) == 2 and all(e.get("exec_token",0)>0 for e in execs) and execs[0]["exec_token"]!=execs[1]["exec_token"]
        failures = events("exec-fail", "process_exec_failed")
        result["checks"]["failed_exec_result"] = bool(failures and failures[0]["retval"] == -2)
        writes = [e for e in events("ptrace", "ptrace") if e.get("request") == 5]
        result["checks"]["owned_child_ptrace_target"] = bool(writes and writes[0]["retval"] == 0 and writes[0].get("target_process_key"))
        exits = events("thread-exec", "thread_exit")
        result["checks"]["thread_vs_process_exit"] = any(e.get("process_dead") for e in exits) and any(not e.get("process_dead") for e in exits)
        health = [e for e in rows if e["event_type"] == "monitor_stop"]
        result["final_metrics"] = health[-1]["metrics"] if health else {}
    result["passed"] = all(result["checks"].values())
    (output / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
