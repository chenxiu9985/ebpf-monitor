"""Scoped LSM acceptance test. Creates one temporary cgroup and harmless fixtures.

Exit 77 means this machine could not run LSM acceptance, not a passed test.
"""
import argparse
import errno
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.runtime import doctor


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="out/lsm")
    parser.add_argument("--uid", type=int, default=1000)
    args = parser.parse_args()
    if args.uid < 0:
        parser.error("uid must be nonnegative")
    output = Path(args.out).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "result.json").exists():
        raise RuntimeError("choose a fresh output directory")
    result = {"source": "REAL_LSM_TEST", "environment": doctor(), "uid": args.uid, "status": "not_run", "checks": {}}
    collector = None
    group = Path("/sys/fs/cgroup") / f"ebpf-monitor-test-{os.getpid()}"
    created = False
    try:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            result.update(status="unavailable", reason="test needs root to load BPF and create its dedicated cgroup")
            return 77
        if result["environment"]["bpf_lsm_active"] is not True:
            result.update(status="unavailable", reason="bpf is not confirmed active in /sys/kernel/security/lsm; CONFIG_BPF_LSM alone is insufficient")
            return 77
        try:
            group.mkdir()
            created = True
        except OSError as exc:
            result.update(status="unavailable", reason=f"dedicated cgroup unavailable: {exc}")
            return 77
        with tempfile.TemporaryDirectory(prefix="ebpf-lsm-") as temporary:
            temp = Path(temporary)
            # Isolated fixtures only: test UID must be able to create the side-effect marker.
            temp.chmod(0o777)
            protected, client, target = temp / "protected.txt", temp / "client", temp / "target"
            protected.write_text("harmless fixture\n")
            protected.chmod(0o644)
            subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(ROOT / "tests/fixtures/block_client.c"), "-o", str(client)], check=True)
            shutil.copyfile(client, target)
            client.chmod(0o755)
            target.chmod(0o755)
            counter = 0
            def join():
                (group / "cgroup.procs").write_text(str(os.getpid()))
                os.setgroups([])
                os.setgid(args.uid)
                os.setuid(args.uid)
            def operation(kind, scoped=True):
                nonlocal counter
                counter += 1
                marker = temp / f"marker-{counter}"
                binary = client if kind == "open" else target
                try:
                    proc = subprocess.run([str(binary), kind, str(protected), str(marker)], preexec_fn=join if scoped else None,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                    denied, code = proc.returncode == 77, proc.returncode
                except PermissionError as exc:
                    denied, code = exc.errno == errno.EPERM, -exc.errno
                return {"returncode": code, "denied": denied, "side_effect": marker.exists()}
            for kind in ("open", "exec"):
                check = operation(kind)
                result["checks"][f"baseline_{kind}"] = check
                if check["returncode"] or not check["side_effect"]:
                    raise RuntimeError("baseline failed; cannot attribute denial to LSM")
            with (output / "collector.log").open("w") as log, (output / "events.jsonl").open("w") as events:
                collector = subprocess.Popen([str(ROOT / "build/collector"), "--enforce-cgroup", str(group),
                                               "--enforce-uid", str(args.uid), "--deny-open", str(protected), "--deny-exec", str(target)],
                                              cwd=ROOT, stdout=events, stderr=log)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if collector.poll() is not None:
                        result.update(status="unavailable", reason="LSM collector failed to load/attach; inspect collector.log")
                        return 77
                    if '"event_type":"monitor_start"' in (output / "collector.log").read_text():
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError("LSM readiness timeout")
                for kind in ("open", "exec"):
                    check = operation(kind)
                    result["checks"][f"denied_{kind}"] = check
                    if not check["denied"] or check["side_effect"]:
                        raise RuntimeError(f"{kind} was not denied before side effect")
                    control = operation(kind, scoped=False)
                    result["checks"][f"outside_cgroup_{kind}"] = control
                    if control["returncode"] or not control["side_effect"]:
                        raise RuntimeError("unrelated cgroup affected")
                replacement = temp / "replacement"
                replacement.write_text("new harmless object\n")
                replacement.chmod(0o644)
                replacement.replace(protected)
                check = operation("open")
                result["checks"]["replacement_before_reload"] = check
                if check["returncode"] or not check["side_effect"]:
                    raise RuntimeError("object identity behavior unexpected")
                collector.send_signal(signal.SIGHUP)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and '"policy_reload":"applied"' not in (output / "collector.log").read_text():
                    time.sleep(0.05)
                check = operation("open")
                result["checks"]["replacement_after_reload"] = check
                if not check["denied"] or check["side_effect"]:
                    raise RuntimeError("reloaded object not protected")
                # Invalid reload must retain current policy.
                target.rename(temp / "target-moved")
                collector.send_signal(signal.SIGHUP)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and '"policy_reload":"failed"' not in (output / "collector.log").read_text():
                    time.sleep(0.05)
                check = operation("open")
                result["checks"]["invalid_reload_retains_policy"] = check
                if not check["denied"] or check["side_effect"]:
                    raise RuntimeError("failed reload changed policy")
                collector.kill()
                collector.wait(timeout=5)
                check = operation("open")
                result["checks"]["crash_releases_links"] = check
                if check["returncode"] or not check["side_effect"]:
                    raise RuntimeError("policy unexpectedly persisted after crash")
            result["status"] = "passed"
            return 0
    except Exception as exc:
        result.update(status="failed", reason=str(exc))
        return 1
    finally:
        if collector and collector.poll() is None:
            collector.terminate()
            try:
                collector.wait(timeout=5)
            except subprocess.TimeoutExpired:
                collector.kill()
                collector.wait(timeout=2)
        if created:
            try:
                group.rmdir()
            except OSError as exc:
                result["cleanup_error"] = str(exc)
        (output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
