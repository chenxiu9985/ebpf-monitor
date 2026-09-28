from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import sys
import time
from pathlib import Path

from .model import load_config
from .protocol import Decoder
from .runtime import Pipeline, doctor, process_snapshot
from .storage import Store, report


def parser():
    p = argparse.ArgumentParser(description="eBPF runtime monitor: replay, listen, query, report, doctor")
    subs = p.add_subparsers(dest="command", required=True)
    subs.add_parser("doctor")
    for name in ("replay", "listen"):
        sub = subs.add_parser(name)
        sub.add_argument("--db", required=True)
        sub.add_argument("--rules")
        sub.add_argument("--alerts")
        if name == "replay":
            sub.add_argument("input")
        else:
            sub.add_argument("--socket", required=True)
            sub.add_argument("--raw", required=True)
            sub.add_argument("--duration", type=float, default=0)
            sub.add_argument("--no-snapshot", action="store_true")
            sub.add_argument("--exit-on-stop", action="store_true",
                             help="exit after collector EOF and committed monitor_stop (supervised mode)")
    sub = subs.add_parser("query")
    sub.add_argument("--db", required=True)
    sub.add_argument("--rule")
    sub.add_argument("--process")
    sub.add_argument("--since-ns", type=int, default=0)
    sub = subs.add_parser("report")
    sub.add_argument("--db", required=True)
    sub.add_argument("--output", required=True)
    sub = subs.add_parser("demo")
    sub.add_argument("--out", default="out/demo")
    return p


def listen(args, pipeline):
    if not hasattr(socket, "AF_UNIX"):
        raise ValueError("live socket listener requires Linux; use replay on Windows")
    sockpath = Path(args.socket)
    if sockpath.exists():
        raise ValueError("socket path already exists; stop its owner and remove stale socket explicitly")
    stopped = False
    reload_pending = False
    def stop(_sig, _frame):
        nonlocal stopped
        stopped = True
    def reload_rules(_sig, _frame):
        nonlocal reload_pending
        reload_pending = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    def apply_reload():
        nonlocal reload_pending
        if not reload_pending:
            return
        reload_pending = False
        try:
            config = load_config(args.rules)
            pipeline.flush()
            pipeline.engine.reload(config)
            print(json.dumps({"rule_reload": "applied", "version": config["version"]}), file=sys.stderr)
        except (ValueError, OSError) as exc:
            print(json.dumps({"rule_reload": "rejected", "error": str(exc)}), file=sys.stderr)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload_rules)
    deadline = time.monotonic() + args.duration if args.duration else float("inf")
    started = set()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(sockpath))
        os.chmod(sockpath, 0o600)
        server.listen(1)
        server.settimeout(0.2)
        while not stopped and time.monotonic() < deadline:
            apply_reload()
            try:
                connection, _ = server.accept()
            except socket.timeout:
                pipeline.flush()
                continue
            with connection:
                connection.settimeout(0.2)
                decoder = Decoder()
                stop_event = None
                while not stopped and time.monotonic() < deadline:
                    apply_reload()
                    try:
                        data = connection.recv(65536)
                    except socket.timeout:
                        pipeline.flush()
                        continue
                    if not data:
                        try:
                            decoder.finish()
                        except ValueError as exc:
                            print(json.dumps({"transport_error": str(exc)}), file=sys.stderr)
                            if args.exit_on_stop:
                                raise
                            stop_event = None
                        # Commit SQLite and flush logs before acknowledging the
                        # final event. EOF prevents accepting a truncated tail.
                        pipeline.flush()
                        if stop_event and stop_event.get("shutdown_ack_required"):
                            ack_id = stop_event["event_id"]
                            if not ack_id.isascii() or any(c.isspace() for c in ack_id) or len(ack_id) > 384:
                                raise ValueError("invalid shutdown acknowledgement identity")
                            connection.settimeout(1.0)
                            connection.sendall(f"COMMITTED {ack_id}\n".encode("ascii"))
                            print(json.dumps({"shutdown_committed": ack_id}), file=sys.stderr)
                        if args.exit_on_stop:
                            if not stop_event:
                                raise ValueError("collector disconnected without monitor_stop")
                            stopped = True
                        break
                    for event in decoder.feed(data):
                        if stop_event is not None:
                            raise ValueError("event received after monitor_stop")
                        pipeline.push(event)
                        if event["event_type"] == "monitor_stop":
                            stop_event = event
                        if event["event_type"] == "monitor_start" and not event.get("pid_namespace_is_host", False):
                            print(json.dumps({"snapshot": "unavailable", "reason": "collector is not in host PID namespace; live process events remain enabled"}), file=sys.stderr)
                        if event["event_type"] == "monitor_start" and event.get("pid_namespace_is_host", False) and event["event_id"] not in started and not args.no_snapshot:
                            started.add(event["event_id"])
                            for snapshot in process_snapshot(event["host_id"], event["boot_id"]):
                                snapshot["monotonic_ns"] = event["monotonic_ns"]
                                pipeline.push(snapshot)
            pipeline.flush()
    finally:
        server.close()
        sockpath.unlink(missing_ok=True)
        pipeline.flush()


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command == "doctor":
        print(json.dumps(doctor(), indent=2, ensure_ascii=False))
        return 0
    if args.command == "demo":
        from .scenarios import demo
        demo(args.out)
        return 0
    store = Store(args.db)
    try:
        if args.command == "query":
            for a in store.alerts(args.rule, args.process, args.since_ns):
                print(json.dumps(a, ensure_ascii=False))
        elif args.command == "report":
            report(store, args.output)
        else:
            pipeline = Pipeline(load_config(args.rules), store, raw=getattr(args, "raw", None), alerts=args.alerts, live=args.command == "listen")
            if args.command == "replay":
                with Path(args.input).open(encoding="utf-8") as stream:
                    for number, line in enumerate(stream, 1):
                        try:
                            pipeline.push(json.loads(line))
                        except (ValueError, TypeError) as exc:
                            raise ValueError(f"line {number}: {exc}") from exc
                pipeline.flush()
            else:
                listen(args, pipeline)
            print(json.dumps({**pipeline.engine.metrics, "loss_epoch": pipeline.engine.loss_epoch}, ensure_ascii=False))
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"monitor error: {error}", file=sys.stderr)
        raise SystemExit(1)
