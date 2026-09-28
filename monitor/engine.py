from __future__ import annotations

import hashlib
import heapq
import os
import posixpath
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class Process:
    key: str
    parent: str = ""
    exe: str = ""
    generation: int = 0
    exec_event: str = ""
    exec_time: int = 0
    touched: int = 0
    exited: int = 0
    origin: tuple = ()


class Engine:
    def __init__(self, config):
        self.config = config
        self.processes: OrderedDict[str, Process] = OrderedDict()
        self.seen: OrderedDict[str, None] = OrderedDict()
        self.temp = {}
        self.preload = {}
        self.loss_epoch = 0
        self.loss_counters = {}
        self.exit_heap = []
        self.exit_serial = 0
        self.last_time = 0
        self.metrics = {"processed": 0, "duplicates": 0, "late": 0, "evicted": 0, "alerts": 0}
        self._refresh_objects()

    def _refresh_objects(self):
        self.sensitive_objects = {}
        if os.name == "posix":
            for path in self.config["sensitive_paths"]:
                try:
                    st = os.stat(path)
                    self.sensitive_objects[((os.major(st.st_dev) << 20) | os.minor(st.st_dev), st.st_ino)] = path
                except OSError:
                    pass

    def reload(self, config):
        # The caller validates the complete config first; old chains cannot cross versions.
        self.config = config
        self._refresh_objects()
        self.temp.clear()
        self.preload.clear()

    def lineage(self, key):
        if not key:
            return []
        p = self.processes.get(key)
        if not p:
            return [{"process_key": key, "exe": "", "missing": True}]
        # Ancestor image identities are frozen when the child is first observed.
        # A later parent exec/exit/cache eviction cannot rewrite its child's origin.
        node = {"process_key": key, "exe": p.exe, "generation": p.generation,
                "exec_event": p.exec_event, "exec_time": p.exec_time, "parent_process_key": p.parent}
        return [node, *(dict(n) for n in p.origin)]

    def _temporary(self, path):
        if not path.startswith("/"):
            return False
        path = posixpath.normpath(path)
        return any(path.startswith(root.rstrip("/") + "/") for root in self.config["temporary_roots"])

    def _expire_exited(self):
        # Live processes need no expiry work. Keep exact event-time semantics,
        # including a changed TTL after reload and strict `age > ttl` boundary.
        cutoff = self.last_time - self.config["exit_retention_seconds"] * 1_000_000_000
        while self.exit_heap and self.exit_heap[0][0] < cutoff:
            exited, _, process = heapq.heappop(self.exit_heap)
            if self.processes.get(process.key) is process and process.exited == exited:
                del self.processes[process.key]
        # Stale entries from evictions/reused keys must not grow without bound.
        if len(self.exit_heap) > 2 * self.config["max_processes"] + 64:
            self.exit_heap = []
            for process in self.processes.values():
                if process.exited:
                    self.exit_serial += 1
                    self.exit_heap.append((process.exited, self.exit_serial, process))
            heapq.heapify(self.exit_heap)

    def _excepted(self, rule, event, process):
        return any(x["rule"] == rule and x["exe"] == process.exe and x["uid"] == event.get("uid")
                   for x in self.config["exceptions"])

    def _alert(self, rule, event, process, evidence, explanation, severity="medium"):
        if rule not in self.config["enabled"] or self._excepted(rule, event, process):
            return None
        evidence = list(dict.fromkeys(evidence))
        digest = hashlib.sha256((str(self.config["version"]) + rule + "|".join(evidence)).encode()).hexdigest()[:24]
        lineage = self.lineage(process.key)
        quality = []
        # Bit 16 records kernel pathname provenance, not missing evidence.
        if event.get("quality_flags", 0) & ~16:
            quality.append("capture_fields_incomplete")
        if event.get("late"):
            quality.append("late_event")
        if any(n.get("missing") for n in lineage):
            quality.append("ancestry_incomplete")
        return {"alert_id": digest, "rule_id": rule, "rule_version": self.config["version"],
                "monotonic_ns": event["monotonic_ns"], "process_key": process.key,
                "exe": process.exe, "severity": severity, "confidence": "reduced" if quality else "contextual",
                "explanation": explanation, "result_state": event.get("result_state", "unknown"),
                "action_state": "audit", "evidence_ids": evidence, "lineage": lineage,
                "quality": quality, "loss_epoch": self.loss_epoch}

    def process(self, event):
        eid, now = event["event_id"], event["monotonic_ns"]
        if eid in self.seen:
            self.metrics["duplicates"] += 1
            return []
        self.seen[eid] = None
        if len(self.seen) > 65536:
            self.seen.popitem(last=False)
        self.metrics["processed"] += 1
        late = now < self.last_time
        if late:
            event = {**event, "late": True}
            self.metrics["late"] += 1
        self.last_time = max(now, self.last_time)
        threshold = self.last_time - self.config["window_seconds"] * 1_000_000_000
        self.temp = {k: v for k, v in self.temp.items() if v["time"] >= threshold}
        self.preload = {k: v for k, v in self.preload.items() if v["time"] >= threshold}
        kind = event["event_type"]
        if kind.startswith("monitor_"):
            values = event.get("metrics", {})
            if any(values.get(k, 0) > self.loss_counters.get(k, 0) for k in ("ring_lost", "map_fail", "queue_lost", "transport_disconnects", "unpaired")):
                self.loss_epoch += 1
                self.temp.clear()
                self.preload.clear()
            if kind == "monitor_start":
                self.temp.clear()
                self.preload.clear()
            self.loss_counters = values
            return []
        key = event["process_key"]
        p = self.processes.get(key)
        if p is None:
            parent_key = event.get("parent_process_key", "")
            parent = self.processes.get(parent_key)
            p = Process(key=key, parent=parent_key,
                        exe=parent.exe if parent and kind == "process_fork" else event.get("exe", ""),
                        origin=tuple(self.lineage(parent_key)[:63]))
            self.processes[key] = p
        self.processes.move_to_end(key)
        p.touched = max(p.touched, now)
        if kind == "process_snapshot" and not p.exec_event:
            p.exe = event.get("exe", "")
        if kind == "process_exec" and not late:
            p.exe = event.get("exe") or event.get("path", "")
            p.generation += 1
            p.exec_event = eid
            p.exec_time = now
            self.preload.pop(key, None)
            self.temp.pop(key, None)
        if kind == "thread_exit" and event.get("process_dead"):
            p.exited = now
            if now:
                self.exit_serial += 1
                heapq.heappush(self.exit_heap, (now, self.exit_serial, p))
        # Retain the fork origin: reparenting must not rewrite recorded history.
        while len(self.processes) > self.config["max_processes"]:
            evicted, _ = self.processes.popitem(last=False)
            self.temp.pop(evicted, None)
            self.preload.pop(evicted, None)
            self.metrics["evicted"] += 1
        self._expire_exited()

        alerts = []
        def emit(rule, evidence, explanation, severity="medium"):
            a = self._alert(rule, event, p, evidence, explanation, severity)
            if a:
                alerts.append(a)

        if kind == "policy_denied":
            a = {"alert_id": hashlib.sha256(eid.encode()).hexdigest()[:24],
                 "rule_id": "LSM", "rule_version": event.get("policy_version", 0),
                 "monotonic_ns": now, "process_key": key, "exe": p.exe, "severity": "high",
                 "explanation": "内核 LSM 拒绝了限定对象操作", "result_state": "failed",
                 "action_state": "denied", "evidence_ids": [eid], "lineage": self.lineage(key),
                 "quality": [], "confidence": "policy_match", "loss_epoch": self.loss_epoch}
            alerts.append(a)
        if kind == "ptrace" and event.get("request") in (4, 5):
            emit("R02", [eid], "观察到 ptrace 写内存请求；操作结果单列，不代表已证实恶意注入", "high")
        path = event.get("path", "")
        preload_path = self.config["preload_config"]
        if ((kind == "file_open" and path == preload_path and event.get("flags", 0) & (1 | 2 | 512)) or
                (kind == "file_rename" and event.get("path2") == preload_path) or
                (kind == "file_unlink" and path == preload_path)):
            emit("R03", [eid], "preload 配置写意图/替换/删除事件；不推断已成功修改内容")
        if kind == "process_exec":
            env = event.get("env", {})
            present = bool(env.get("LD_PRELOAD") or env.get("LD_LIBRARY_PATH"))
            if present:
                emit("R03", [eid], "执行环境出现动态加载相关配置，不等于共享库已加载")
                values = ":".join(env.values()).replace(" ", ":").split(":")
                if not late and any(self._temporary(x) for x in values) and not self._excepted("R03", event, p):
                    self.preload[key] = {"time": now, "generation": p.generation, "ids": [eid]}
            lineage = self.lineage(key)
            ancestors = lineage[1:]
            shell_index = next((i for i, n in enumerate(ancestors) if n["exe"] in self.config["shell_executables"] and n.get("exec_event")), None)
            service = None if shell_index is None else next((n for n in ancestors[shell_index+1:] if n["exe"] in self.config["service_executables"]), None)
            if self._temporary(p.exe) and service:
                ids = [ancestors[shell_index]["exec_event"], eid]
                emit("R04", ids, "服务后代 shell 执行临时目录程序；目录匹配是风险线索，不证明实际可写", "high")
                shell_time = ancestors[shell_index]["exec_time"]
                if (not late and not self._excepted("R04", event, p) and
                        0 <= now - shell_time <= self.config["window_seconds"] * 1_000_000_000):
                    # The complete sequence starts at shell execution, not at the temporary binary.
                    self.temp[key] = {"time": shell_time, "generation": p.generation, "ids": ids}
        object_match = (event.get("device", 0), event.get("inode", 0)) in self.sensitive_objects
        if kind == "file_open" and (path in self.config["sensitive_paths"] or object_match):
            emit("R01", [eid], "非例外主体打开敏感对象；成功打开与读取内容严格区分", "high")
            if not late and not self._excepted("R01", event, p):
                for ancestor in self.lineage(key):
                    token = self.temp.get(ancestor["process_key"])
                    if token and token["generation"] == ancestor.get("generation") and 0 <= now-token["time"] <= self.config["window_seconds"]*1_000_000_000:
                        emit("C01", token["ids"]+[eid], "服务 → shell → 临时程序 → 敏感对象访问的时间窗口关联", "high")
                        self.temp.pop(ancestor["process_key"], None)
                        break
                token = self.preload.get(key)
                if token and token["generation"] == p.generation and 0 <= now-token["time"] <= self.config["window_seconds"]*1_000_000_000:
                    emit("C02", token["ids"]+[eid], "同一执行映像的可疑 preload 配置与后续敏感访问相关联；不证明库加载", "high")
                    self.preload.pop(key, None)
        self.metrics["alerts"] += len(alerts)
        return alerts
