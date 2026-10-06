from __future__ import annotations

import heapq
import json
import os
import platform
import shutil
import time
from pathlib import Path

from .engine import Engine
from .model import validate_event
from .response import ControlClient, ResponseManager
from .capture import CapturePlan


def doctor():
    def read(path):
        try:
            return Path(path).read_text().strip()
        except OSError:
            return None
    linux = platform.system() == "Linux"
    lsm = read("/sys/kernel/security/lsm")
    info = {"os": platform.platform(), "kernel": platform.release(), "architecture": platform.machine(),
            "uid": os.getuid() if hasattr(os, "getuid") else None,
            "btf_readable": os.access("/sys/kernel/btf/vmlinux", os.R_OK), "active_lsm": lsm,
            "bpf_lsm_active": "bpf" in lsm.split(",") if lsm else None,
            "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").exists(),
            "tools": {x: shutil.which(x) for x in ("clang", "cc", "make", "pkg-config", "bpftool")},
            "tracepoints": {}, "load_verified": False,
            "note": "Static capability inventory only; run integration tests to prove loading and hook coverage."}
    for group, event in (("sched", "sched_process_exec"), ("sched", "sched_process_fork"),
                         ("syscalls", "sys_enter_openat2"), ("syscalls", "sys_enter_ptrace")):
        info["tracepoints"][f"{group}/{event}"] = any((Path(root) / "events" / group / event / "format").exists()
                                                        for root in ("/sys/kernel/tracing", "/sys/kernel/debug/tracing")) if linux else False
    memory = read("/proc/meminfo")
    if memory:
        info["mem_total_kib"] = int(memory.splitlines()[0].split()[1])
    return info


def process_snapshot(host_id, boot_id):
    """Called after monitor_start: kernel probes are already attached and buffering."""
    if platform.system() != "Linux":
        return []
    ticks = os.sysconf("SC_CLK_TCK")
    rows = {}
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            stat = (directory / "stat").read_text()
            fields = stat[stat.rfind(")") + 2:].split()
            start_ticks, parent = int(fields[19]), int(fields[1])
            exe = os.readlink(directory / "exe")
            again = (directory / "stat").read_text()
            if int(again[again.rfind(")") + 2:].split()[19]) != start_ticks:
                continue
            rows[int(directory.name)] = (start_ticks * 1_000_000_000 // ticks, parent, exe)
        except (OSError, ValueError, IndexError):
            continue
    result, now = [], time.monotonic_ns()
    for pid, (start, parent, exe) in rows.items():
        key = f"{host_id}:{boot_id}:{pid}:{start}"
        parent_start = rows.get(parent, (0, 0, ""))[0]
        result.append({"schema_version": 1, "event_id": f"snapshot:{now}:{pid}", "event_type": "process_snapshot",
                       "monotonic_ns": now, "host_id": host_id, "boot_id": boot_id,
                       "process_key": key, "parent_process_key": f"{host_id}:{boot_id}:{parent}:{parent_start}",
                       "process_start_ns": start, "snapshot_tick_ns": 1_000_000_000 // ticks,
                       "tgid": pid, "ppid": parent, "exe": exe, "quality_flags": 4})
    return result


class RotatingJSONL:
    def __init__(self, path, max_bytes=10*1024*1024, backups=5):
        self.path, self.max_bytes, self.backups = Path(path), max_bytes, backups
        self.stream = None
        self.size = self.path.stat().st_size if self.path.exists() else 0

    def write(self, record):
        self.write_encoded(json.dumps(record, ensure_ascii=False))

    def write_encoded(self, encoded):
        if self.size >= self.max_bytes:
            self.close()
            oldest = Path(str(self.path) + f".{self.backups}")
            oldest.unlink(missing_ok=True)
            for i in range(self.backups - 1, 0, -1):
                previous = Path(str(self.path) + f".{i}")
                if previous.exists():
                    previous.replace(str(self.path) + f".{i+1}")
            self.path.replace(str(self.path) + ".1")
            self.size = 0
        if self.stream is None:
            self.stream = self.path.open("a", encoding="utf-8", newline="\n", buffering=65536)
        line = encoded + "\n"
        self.stream.write(line)
        self.size += len(line.encode("utf-8"))

    def close(self):
        if self.stream:
            self.stream.close()
            self.stream = None


class Pipeline:
    def __init__(self, config, store, raw=None, alerts=None, live=False, control_socket=None):
        self.engine, self.store = Engine(config), store
        self.raw = RotatingJSONL(raw) if raw else None
        self.alert_sink = RotatingJSONL(alerts) if alerts else None
        self.heap, self.serial, self.maximum = [], 0, 0
        self.aliases = {}
        self.snapshot_candidates = {}
        self.live = live
        self.response = ResponseManager(config, store, live, ControlClient(control_socket) if control_socket else None)
        self.session_id = None
        self.capture = CapturePlan(config)

    def push(self, event):
        e = validate_event(event)
        if self.live:
            e["received_ns"] = time.monotonic_ns()
        if self.session_id != e.get("session_id"):
            self.flush()
            self.aliases.clear()
            self.snapshot_candidates.clear()
            self.maximum = 0
            self.session_id = e.get("session_id")
            self.capture.loading.clear()
        if e["event_type"] == "process_snapshot":
            self.snapshot_candidates[(e.get("host_id"), e.get("boot_id"), e["tgid"])] = e
        elif "tgid" in e:
            lookup = (e.get("host_id"), e.get("boot_id"), e["tgid"])
            snapshot = self.snapshot_candidates.get(lookup)
            if snapshot and 0 <= e.get("process_start_ns", -1) - snapshot["process_start_ns"] < snapshot["snapshot_tick_ns"]:
                # Align /proc tick precision with exact BPF nanoseconds without PID-only merges.
                self.aliases[e["process_key"]] = snapshot["process_key"]
        if e.get("process_key") in self.aliases:
            e["process_key"] = self.aliases[e["process_key"]]
        parent_key = e.get("parent_process_key", "")
        if parent_key and parent_key not in self.aliases:
            try:
                prefix, pid, start = parent_key.rsplit(":", 2)
                snapshot = self.snapshot_candidates.get((e.get("host_id"), e.get("boot_id"), int(pid)))
                if snapshot and 0 <= int(start) - snapshot["process_start_ns"] < snapshot["snapshot_tick_ns"]:
                    self.aliases[parent_key] = snapshot["process_key"]
            except ValueError:
                pass
        if parent_key in self.aliases:
            e["parent_process_key"] = self.aliases[parent_key]
        source_key = e.get("service_process_key", "")
        if source_key:
            try:
                prefix, pid, start = source_key.rsplit(":", 2)
                snapshot = self.snapshot_candidates.get((e.get("host_id"), e.get("boot_id"), int(pid)))
                if snapshot and 0 <= int(start)-snapshot["process_start_ns"] < snapshot["snapshot_tick_ns"]:
                    self.aliases[source_key] = snapshot["process_key"]
            except ValueError:
                pass
            e["service_process_key"] = self.aliases.get(source_key, source_key)
        self.serial += 1
        self.maximum = max(self.maximum, e["monotonic_ns"])
        heapq.heappush(self.heap, (e["monotonic_ns"], self.serial, e))
        watermark = self.maximum - self.engine.config["reorder_ms"] * 1_000_000
        self.flush(watermark)
        if len(self.heap) > 8192:
            # Bounded memory: forced early processing is visible in the event quality.
            self.heap[0][2]["quality_flags"] = self.heap[0][2].get("quality_flags", 0) | 4
            self.flush(self.heap[0][0])

    def flush(self, watermark=None):
        while self.heap and (watermark is None or self.heap[0][0] <= watermark):
            _, _, e = heapq.heappop(self.heap)
            self.capture.config = self.engine.config
            keep = self.capture.keep(e, self.engine.sensitive_objects)
            if keep:
                new, body = self.store.event_with_body(e)
                if not new:
                    self.engine.metrics["duplicates"] += 1
                    continue
                if self.raw:
                    self.raw.write_encoded(body)
            # All records still update identity, lineage, event time and cache
            # order. Filtering those updates changed ancestry in a real replay.
            self.response.denial(e)
            for a in self.engine.process(e):
                if not keep:
                    _, body = self.store.event_with_body(e)
                    if self.raw:
                        self.raw.write_encoded(body)
                    keep = True
                    self.capture.filtered -= 1
                if self.live:
                    a["analysis_time_ns"] = time.monotonic_ns()
                    a["delivery_delay_ns"] = max(0, a["analysis_time_ns"] - a["monotonic_ns"])
                if self.store.alert(a):
                    self.response.config = self.engine.config
                    self.response.consider(a, e)
                    if self.alert_sink:
                        self.alert_sink.write(a)
        if watermark is None:
            self.store.flush()
            if self.raw:
                self.raw.close()
            if self.alert_sink:
                self.alert_sink.close()
