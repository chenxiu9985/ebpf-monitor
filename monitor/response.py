"""Restricted, independent control transport. Replay cannot send real requests."""
from __future__ import annotations

import hashlib
import socket
import time

CONTROL_VERSION = 1
MAX_CONTROL = 1024


def request_bytes(request):
    """Single seqpacket; strings are fixed hexadecimal IDs, no paths or PID-only actions."""
    automatic = "cgroup_id" in request
    expected = {"cgroup_id"} if automatic else set()
    if set(request) != expected | {"verb", "request_id", "session_id", "rule_version", "evidence_id", "tgid",
                        "start_ns", "exec_token", "uid", "object_id", "ttl_ms"}:
        raise ValueError("invalid control fields")
    if request["verb"] not in {"APPLY", "QUERY", "REVOKE"}:
        raise ValueError("unsupported control verb")
    for field in ("request_id", "session_id", "evidence_id"):
        value = request[field]
        if not isinstance(value, str) or not 1 <= len(value) <= (255 if field == "session_id" else 64):
            raise ValueError("invalid control identity")
        if not all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:-_" for c in value):
            raise ValueError("invalid control identity")
    for field in ("rule_version", "tgid", "start_ns", "exec_token", "uid", "object_id", "ttl_ms"):
        if type(request[field]) is not int or not 0 <= request[field] < 2**64:
            raise ValueError("invalid control number")
    if automatic and (type(request["cgroup_id"]) is not int or not 0 < request["cgroup_id"] < 2**64):
        raise ValueError("invalid runtime cgroup identity")
    if not 1 <= request["ttl_ms"] <= 30000 or request["object_id"] != (0 if automatic else 1):
        raise ValueError("unsupported object or TTL")
    payload = ("V4 2 " if automatic else "V4 1 ") + " ".join(str(request[f]) for f in (
        "verb", "request_id", "session_id", "rule_version", "evidence_id", "tgid", "start_ns",
        "exec_token", "uid", "object_id", "ttl_ms"))
    if automatic:
        payload += " " + str(request["cgroup_id"])
    return payload.encode("ascii")


class ControlClient:
    def __init__(self, path, timeout=0.25):
        self.path, self.timeout = path, timeout

    def exchange(self, request):
        import json
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
            connection.settimeout(self.timeout)
            connection.connect(self.path)
            connection.sendall(request_bytes(request))
            payload = connection.recv(MAX_CONTROL + 1)
            if not payload or len(payload) > MAX_CONTROL:
                raise ValueError("invalid control reply")
            reply = json.loads(payload)
            if not isinstance(reply, dict) or type(reply.get("control_version")) is not int or reply.get("control_version") != (2 if "cgroup_id" in request else CONTROL_VERSION) or reply.get("request_id") != request["request_id"] or reply.get("state") not in {
                "applied", "rejected", "expired", "revoked", "unknown"}:
                raise ValueError("invalid control acknowledgement")
            for field in ("policy_id", "update_before_ns", "update_after_ns", "expires_ns", "inode", "device"):
                if type(reply.get(field)) is not int or not 0 <= reply[field] < 2**64:
                    raise ValueError("invalid control acknowledgement time or scope")
            if reply["state"] == "applied" and (not reply["policy_id"] or
                    not 0 < reply["update_before_ns"] <= reply["update_after_ns"] <= reply["expires_ns"]):
                raise ValueError("invalid application interval")
            if "cgroup_id" in request and reply["state"] == "applied" and any(
                    type(reply.get(k)) is not int or reply[k] != request[k] for k in ("uid", "cgroup_id", "object_id")):
                raise ValueError("invalid runtime scope acknowledgement")
            return reply


class ResponseManager:
    def __init__(self, config, store, live=False, client=None):
        self.config, self.store, self.live = config, store, live
        self.client = client

    def consider(self, alert, event):
        if alert["rule_id"] != "R04":
            return
        mode = self.config["response_mode"]
        reasons = list(alert["evidence_quality"]["response_prohibited_reasons"])
        if not self.live:
            reasons.append("offline_replay")
        if mode == "audit":
            reasons.append("audit_mode")
        if event.get("result_state") != "succeeded":
            reasons.append("execution_not_successful")
        # Every rule involved in A can veto action, even if R04 emitted an alert.
        for item in self.config["exceptions"]:
            if item["rule"] in {"R01", "R04", "C01"} and item["exe"] == alert["exe"] and item["uid"] == event.get("uid"):
                reasons.append("rule_exception")
        automatic = self.config.get("response_scope", "auto") == "auto"
        if automatic and not event.get("cgroup_id"):
            reasons.append("runtime_cgroup_unknown")
        if automatic and not event.get("service_id"):
            reasons.append("service_not_kernel_registered")
        rid = hashlib.sha256((event.get("session_id", "") + alert["alert_id"]).encode()).hexdigest()[:32]
        row = {"request_id": rid, "alert_id": alert["alert_id"], "evidence_ids": alert["evidence_ids"],
               "mode": mode, "state": "audit", "decision_ns": time.monotonic_ns(),
               "reasons": list(dict.fromkeys(reasons)), "process_key": alert["process_key"],
               "exec_token": event.get("exec_token", 0)}
        if reasons:
            self.store.response(row)
            return
        request = dict(verb="APPLY", request_id=rid, session_id=event["session_id"],
                       rule_version=alert["rule_version"], evidence_id=alert["alert_id"],
                       tgid=event["tgid"], start_ns=event["process_start_ns"],
                       exec_token=event["exec_token"], uid=event["uid"], object_id=1,
                       ttl_ms=self.config["response_ttl_ms"])
        if automatic:
            request.update(object_id=0, cgroup_id=event["cgroup_id"])
        row["request"] = request
        if mode == "shadow":
            row["state"] = "shadow"
            self.store.response(row)
            return
        if not self.client:
            row.update(state="rejected", reasons=["control_unavailable"])
            self.store.response(row)
            return
        row.update(state="requested", request=request, request_time_ns=time.monotonic_ns())
        self.store.response(row)
        self.store.flush()  # persist intent before external mutation
        try:
            reply = self.client.exchange(request)
        except (OSError, ValueError):
            row.update(state="timed_out", reasons=["application_unknown_until_query"])
            self.store.response(row)
            try:
                reply = self.client.exchange({**request, "verb": "QUERY"})
            except (OSError, ValueError):
                row.update(state="unknown")
                self.store.response(row)
                return
        row.update(reply, confirmation_ns=time.monotonic_ns())
        self.store.response(row)

    def denial(self, event):
        if event["event_type"] == "monitor_control":
            row = {k: v for k, v in event.items() if not k.startswith("_")}
            previous = self.store.response_context(request_id=row["request_id"])
            row["alert_id"] = previous.get("alert_id")
            self.store.response(row)
        if event.get("dynamic_policy_id"):
            previous = self.store.response_context(policy_id=event["dynamic_policy_id"], session_id=event.get("session_id"))
            self.store.response({"request_id": previous.get("request_id", "kernel:" + str(event["dynamic_policy_id"])),
                                 "alert_id": previous.get("alert_id"),
                                 "session_id": event.get("session_id"),
                                 "state": "denied", "policy_id": event["dynamic_policy_id"],
                                 "event_id": event["event_id"], "monotonic_ns": event["monotonic_ns"]})
