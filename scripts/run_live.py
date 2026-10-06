"""Own both child lifecycles so Ctrl+C stops capture before stopping analysis."""
from __future__ import annotations

import argparse
import datetime
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.model import load_config
from monitor.assets import write_manifest


def supervise(args, collector_command=None):
    if os.name != "posix":
        raise ValueError("live monitoring requires Linux")
    if not 1 <= args.drain_timeout_ms <= 60000 or args.duration < 0:
        raise ValueError("invalid duration or drain timeout")
    command = collector_command or [str(ROOT / "build/collector")]
    if collector_command is None and os.geteuid() != 0:
        subprocess.run(["sudo", "-v"], check=True)
        command = ["sudo", "-n", *command]
    rules = Path(args.rules).resolve()
    if not rules.is_file():
        raise ValueError(f"rules not found: {rules}")
    config = load_config(rules)
    if getattr(args, "response_mode", None):
        config["response_mode"] = args.response_mode
    scope_args = [getattr(args, x, None) for x in ("control_object", "control_cgroup", "control_target_uid")]
    if any(x is not None for x in scope_args) and not all(x is not None for x in scope_args):
        raise ValueError("legacy scope requires all three --control-* arguments")
    config["response_scope"] = "legacy" if all(x is not None for x in scope_args) else "auto"
    dynamic = config["response_mode"] == "enforce"
    output = Path(args.out).resolve() if args.out else ROOT / "out" / "live-v4" / (
        datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}")
    output.mkdir(parents=True, exist_ok=False)
    rules = output / "rules.json"
    rules.write_text(json.dumps(config, indent=2), encoding="utf-8")
    manifest = output / "response-assets.tsv"
    registry_args = []
    if config["response_scope"] == "auto" and (dynamic or
            (config["sensitive_paths"] and config["service_executables"])):
        write_manifest(config, manifest)
        if not dynamic:
            registry_args = ["--asset-manifest", str(manifest)]
    control_args = []
    if dynamic:
        control_args = ["--control-peer-uid", str(os.getuid())]
        if config["response_scope"] == "auto":
            control_args += ["--control-manifest", str(manifest)]
        else:
            control_args += ["--control-object", str(Path(args.control_object).resolve()),
                             "--control-cgroup", args.control_cgroup,
                             "--control-target-uid", str(args.control_target_uid)]
    stopped = False
    def request_stop(_sig, _frame):
        nonlocal stopped
        stopped = True
    previous = {sig: signal.signal(sig, request_stop) for sig in (signal.SIGINT, signal.SIGTERM)}
    analyzer = collector = None
    failure = None
    result = {"source": "V4_SUPERVISED_LIVE", "passed": False, "output": str(output), "mode": config["response_mode"], "response_scope": config["response_scope"]}
    print(f"Monitoring output: {output}\nPress Ctrl+C once; capture will stop, then analysis will drain.", flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix="ebpf-v4-") as temporary:
            socket_path = Path(temporary) / "events.sock"
            control_socket = Path(temporary) / "control.sock"
            with (output / "analyzer.log").open("w") as alog, (output / "collector.log").open("w") as clog:
                try:
                    analyzer = subprocess.Popen([
                        sys.executable, "-m", "monitor", "listen", "--socket", str(socket_path),
                        "--db", str(output / "alerts.db"), "--raw", str(output / "events.jsonl"),
                        "--alerts", str(output / "alerts.jsonl"), "--rules", str(rules), "--exit-on-stop",
                        *(["--control-socket", str(control_socket)] if dynamic else []),
                    ], cwd=ROOT, stdout=alog, stderr=alog, start_new_session=True)
                    ready_until = time.monotonic() + 10
                    while not socket_path.exists():
                        if stopped:
                            raise RuntimeError("stopped before collector startup")
                        if analyzer.poll() is not None or time.monotonic() >= ready_until:
                            raise RuntimeError("analyzer startup failed; inspect analyzer.log")
                        time.sleep(0.05)
                    collector = subprocess.Popen([
                        *command, "--socket", str(socket_path), "--exclude-pid", str(analyzer.pid),
                        "--drain-timeout-ms", str(args.drain_timeout_ms),
                        *(["--duration", str(args.duration)] if args.duration else []),
                        *(["--capture-mappings"] if getattr(args, "capture_mappings", False) else []),
                        *registry_args,
                        *(["--control-socket", str(control_socket), *control_args] if dynamic else []),
                    # Keep the terminal session used by sudo -v, but isolate
                    # the process group from foreground Ctrl+C (Python 3.11+).
                    ], cwd=ROOT, stdout=clog, stderr=clog, process_group=0)
                    print(json.dumps({"collector_pid": collector.pid, "analyzer_pid": analyzer.pid}), flush=True)
                    stop_sent = False
                    stop_until = float("inf")
                    while collector.poll() is None:
                        analyzer_done = analyzer.poll() is not None
                        if analyzer_done and analyzer.returncode:
                            failure = f"analyzer failed with status {analyzer.returncode}"
                        # A normal listener may exit just before ACK is read.
                        # SIGTERM is idempotent for a collector already draining;
                        # only its ACK/exit status determines final success.
                        if (stopped or analyzer_done) and not stop_sent:
                            collector.send_signal(signal.SIGTERM)
                            stop_sent = True
                            stop_until = time.monotonic() + args.drain_timeout_ms / 1000 + 5
                        if time.monotonic() >= stop_until:
                            raise RuntimeError("collector exceeded shutdown deadline")
                        time.sleep(0.05)
                    if collector.returncode:
                        raise RuntimeError(f"collector failed with status {collector.returncode}; inspect collector.log")
                    analyzer.wait(timeout=5)
                    if analyzer.returncode:
                        raise RuntimeError(f"analyzer failed with status {analyzer.returncode}")
                    if failure:
                        raise RuntimeError(failure)
                    result["passed"] = True
                finally:
                    # Failure cleanup only; the analyzer stays alive during drain.
                    for child in (collector, analyzer):
                        if child is not None and child.poll() is None:
                            child.terminate()
                            try:
                                child.wait(timeout=args.drain_timeout_ms / 1000 + 2 if child is collector else 3)
                            except subprocess.TimeoutExpired:
                                child.kill()
                                child.wait(timeout=3)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc)
    finally:
        result["collector_exit"] = collector.returncode if collector else None
        result["analyzer_exit"] = analyzer.returncode if analyzer else None
        result["stop_requested"] = stopped
        rows = []
        collector_log = output / "collector.log"
        if collector_log.exists():
            for line in collector_log.read_text(errors="replace").splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
        result["shutdown"] = next((r for r in reversed(rows) if "shutdown_unsent" in r), {})
        result["final_metrics"] = next((r["metrics"] for r in reversed(rows) if "metrics" in r), {})
        shutdown = result["shutdown"]
        result["passed"] = bool(result["passed"] and shutdown.get("shutdown_acknowledged") is True
                                and shutdown.get("shutdown_unsent") == 0 and shutdown.get("shutdown_error") == 0)
        result["capture_loss_free"] = bool(result["passed"] and all(
            result["final_metrics"].get(k) == 0 for k in ("ring_lost", "map_fail", "queue_lost", "unpaired", "transport_disconnects")))
        (output / "session.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rules", nargs="?", default=str(ROOT / "rules/default.yaml"))
    parser.add_argument("--out", help="new output directory; default out/live-v4/<time-pid>")
    parser.add_argument("--response-mode", choices=["audit", "shadow", "enforce"], help="override rules; enforce discovers target UID/cgroup automatically")
    parser.add_argument("--capture-mappings", action="store_true")
    parser.add_argument("--control-object")
    parser.add_argument("--control-cgroup")
    parser.add_argument("--control-target-uid", type=int)
    parser.add_argument("--duration", type=int, default=0)
    parser.add_argument("--drain-timeout-ms", type=int, default=10000)
    return supervise(parser.parse_args())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"supervisor error: {exc}", file=sys.stderr)
        raise SystemExit(1)
