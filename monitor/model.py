from __future__ import annotations

import json
from pathlib import Path

RULES = {"R01", "R02", "R03", "R04", "C01", "C02"}
EVENTS = {"process_fork", "process_exec", "process_exec_failed", "thread_exit",
          "file_open", "ptrace", "file_rename", "file_unlink", "policy_denied",
          "process_snapshot", "monitor_start", "monitor_health", "monitor_stop", "monitor_control", "monitor_registry", "file_mapping"}
DEFAULTS = dict(version=1, window_seconds=30, reorder_ms=200, max_processes=8192,
                exit_retention_seconds=60, enabled=sorted(RULES),
                sensitive_paths=["/etc/shadow", "/etc/gshadow"], preload_config="/etc/ld.so.preload",
                temporary_roots=["/tmp", "/var/tmp", "/dev/shm"],
                service_executables=["/usr/sbin/nginx", "/usr/sbin/apache2", "/usr/sbin/sshd", "/usr/sbin/cron", "/usr/bin/demo-service"],
                shell_executables=["/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash"],
                exceptions=[], response_mode="audit", response_scope="auto", response_ttl_ms=5000,
                capture_profile="full")


def load_config(path: str | Path | None = None) -> dict:
    data = {}
    if path:
        text = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            try:
                import yaml
            except ImportError as exc:
                raise ValueError("YAML configuration requires PyYAML; install requirements.txt") from exc
            try:
                data = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                raise ValueError(f"invalid YAML configuration: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("configuration must be a mapping")
    if set(data) - set(DEFAULTS):
        raise ValueError(f"unknown configuration fields: {sorted(set(data) - set(DEFAULTS))}")
    config = {**DEFAULTS, **data}
    if config["response_scope"] not in {"auto", "legacy"}:
        raise ValueError("invalid response scope")
    if config["response_mode"] not in {"audit", "shadow", "enforce"}:
        raise ValueError("invalid response mode")
    if type(config["response_ttl_ms"]) is not int or not 1 <= config["response_ttl_ms"] <= 30000:
        raise ValueError("response TTL must be 1..30000 ms")
    if config["capture_profile"] not in {"full", "rule_related"}:
        raise ValueError("invalid capture profile")
    for field in ("version", "window_seconds", "max_processes", "exit_retention_seconds"):
        if type(config[field]) is not int or config[field] < 1:
            raise ValueError(f"{field} must be a positive integer")
    if config["window_seconds"] > 3600 or config["max_processes"] > 100000:
        raise ValueError("window/process limit exceeds supported bounds")
    if type(config["reorder_ms"]) is not int or not 0 <= config["reorder_ms"] <= 5000:
        raise ValueError("reorder_ms must be between 0 and 5000")
    if not isinstance(config["enabled"], list) or any(not isinstance(x, str) or x not in RULES for x in config["enabled"]):
        raise ValueError("enabled contains unknown rule IDs")
    for name in ("sensitive_paths", "temporary_roots", "service_executables", "shell_executables"):
        if not isinstance(config[name], list) or any(not isinstance(x, str) or not x.startswith("/") for x in config[name]):
            raise ValueError(f"{name} must contain absolute Linux paths")
    if not isinstance(config["preload_config"], str) or not config["preload_config"].startswith("/"):
        raise ValueError("preload_config must be an absolute path")
    if not isinstance(config["exceptions"], list):
        raise ValueError("exceptions must be a list")
    for item in config["exceptions"]:
        if not isinstance(item, dict) or set(item) != {"rule", "exe", "uid"}:
            raise ValueError("exception requires exactly rule, exe, uid")
        if not isinstance(item["rule"], str) or item["rule"] not in RULES or not isinstance(item["exe"], str) or not item["exe"].startswith("/") or type(item["uid"]) is not int or item["uid"] < 0:
            raise ValueError("invalid exception")
    return config


def validate_event(event: dict) -> dict:
    if not isinstance(event, dict) or type(event.get("schema_version")) is not int or event.get("schema_version") not in {1, 2}:
        raise ValueError("unsupported event schema")
    source_version = event["schema_version"]
    event = dict(event)
    if source_version == 1:
        # Legacy identities cannot authorize a kernel operation.
        event.update(schema_version=2, source_schema_version=1, exec_token=0,
                     session_id=event.get("session_id", "legacy:" + str(event.get("boot_id", "unknown"))),
                     clock_domain="CLOCK_MONOTONIC", source_hook="v3_replay_adapter")
    else:
        for name in ("session_id", "clock_domain", "source_hook"):
            if not isinstance(event.get(name), str) or not event[name] or len(event[name]) > 512:
                raise ValueError(f"invalid {name}")
        if event["clock_domain"] != "CLOCK_MONOTONIC":
            raise ValueError("unsupported clock domain")
        if not event["event_type"].startswith("monitor_") and event["event_type"] != "process_snapshot":
            for name in ("exec_token", "process_start_ns", "tgid", "uid"):
                if type(event.get(name)) is not int or not 0 <= event[name] < 2**64:
                    raise ValueError(f"invalid {name}")
    for field in ("event_id", "event_type"):
        if not isinstance(event.get(field), str) or not event[field] or len(event[field]) > 512:
            raise ValueError(f"invalid {field}")
    if event["event_type"] not in EVENTS:
        raise ValueError("unknown event type")
    if "shutdown_ack_required" in event and type(event["shutdown_ack_required"]) is not bool:
        raise ValueError("shutdown_ack_required must be boolean")
    if type(event.get("monotonic_ns")) is not int or event["monotonic_ns"] < 0:
        raise ValueError("invalid monotonic_ns")
    if not event["event_type"].startswith("monitor_"):
        if not isinstance(event.get("process_key"), str) or not event["process_key"]:
            raise ValueError("process event requires process_key")
    if event.get("result_state", "unknown") not in {"succeeded", "failed", "attempted", "unknown"}:
        raise ValueError("invalid result_state")
    if "path_source" in event and event["path_source"] not in ("kernel_filename", "syscall_entry", "unavailable"):
        raise ValueError("invalid path_source")
    if not isinstance(event.get("env", {}), dict):
        raise ValueError("env must be a mapping")
    if "field_quality" in event and (not isinstance(event["field_quality"], dict) or
            any(k not in {"path", "environment", "argv"} or type(v) is not int or v<0 for k,v in event["field_quality"].items())):
        raise ValueError("invalid field quality")
    if "metrics" in event and (not isinstance(event["metrics"], dict) or
            any(not isinstance(k,str) or type(v) is not int or v<0 for k,v in event["metrics"].items())):
        raise ValueError("invalid health counters")
    for field in ("uid", "euid", "tgid", "tid", "ppid", "flags", "request", "quality_flags", "inode", "device", "exec_token", "process_start_ns", "received_ns", "collector_receive_ns", "dynamic_policy_id", "operation_start_ns", "cgroup_id", "service_id", "service_source", "service_tgid", "service_start_ns", "service_token", "protected_object_id"):
        if field in event and (type(event[field]) is not int or event[field] < 0):
            raise ValueError(f"invalid {field}")
    for field in ("exe", "path", "path2", "parent_process_key", "service_process_key", "service_exe"):
        if field in event and (not isinstance(event[field], str) or len(event[field]) > 8192):
            raise ValueError(f"invalid {field}")
    if any(not isinstance(k, str) or not isinstance(v, str) or len(v) > 8192 for k, v in event.get("env", {}).items()):
        raise ValueError("invalid environment entry")
    return dict(event)
