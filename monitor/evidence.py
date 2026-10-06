"""Rule requirements are categorical observations, never probability estimates."""
from __future__ import annotations

REQUIREMENTS = {
    "R01": ("sensitive_open_result",), "R02": ("ptrace_request_result",),
    "R03": ("configuration_observed",),
    "R04": ("service_origin", "shell_exec", "temporary_exec"),
    "C01": ("service_origin", "shell_exec", "temporary_exec", "sensitive_open_result"),
    "C02": ("configuration_observed", "object_open_observed", "file_mapping_observed", "subsequent_sensitive_action"),
    "LSM": ("kernel_denial",),
}


def select_service(lineage):
    candidates = [n for n in lineage if n.get("service_origin")]
    return next((n for n in candidates if n.get("exec_event") or n.get("registration_event")),
                candidates[0] if candidates else None)


def evaluate(rule, records, lineage, loss_intervals=(), observation_start=None):
    records = list(records)
    observed = {}
    reasons = []
    for e in records:
        kind = e["event_type"]
        eid = e["event_id"]
        if e.get("quality_flags", 0) & ~16:
            reasons.append("capture_fields_incomplete:" + eid)
        if e.get("late"):
            reasons.append("late_event:" + eid)
        if not e.get("exec_token") or not e.get("process_start_ns"):
            reasons.append("kernel_identity_unknown:" + eid)
        if e.get("result_state") not in {"succeeded", "failed"}:
            reasons.append("operation_result_unknown:" + eid)
        if kind == "process_exec" and e.get("result_state") == "succeeded":
            if e.get("exe") in e.get("_shells", []):
                observed.setdefault("shell_exec", []).append(eid)
            if e.get("_temporary"):
                observed.setdefault("temporary_exec", []).append(eid)
            if any(e.get("env", {}).values()):
                observed.setdefault("configuration_observed", []).append(eid)
        if kind in {"file_rename", "file_unlink"} or (kind == "file_open" and e.get("_configuration")):
            observed.setdefault("configuration_observed", []).append(eid)
        if kind == "file_open":
            stage = "sensitive_open_result" if e.get("_sensitive") else "object_open_observed"
            if stage != "sensitive_open_result" or e.get("result_state") in {"succeeded", "failed"}:
                observed.setdefault(stage, []).append(eid)
            else:
                observed.setdefault("sensitive_open_attempted", []).append(eid)
            if e.get("_sensitive"):
                observed.setdefault("subsequent_sensitive_action", []).append(eid)
            if stage == "object_open_observed" and e.get("result_state") != "succeeded":
                reasons.append("object_open_not_successful:" + eid)
        if kind == "file_mapping":
            observed.setdefault("file_mapping_attempted", []).append(eid)
            if e.get("result_state") == "succeeded" and e.get("inode"):
                observed.setdefault("file_mapping_observed", []).append(eid)
            else:
                reasons.append("mapping_not_successful:" + eid)
        if kind == "ptrace":
            if e.get("result_state") in {"succeeded", "failed"}:
                observed.setdefault("ptrace_request_result", []).append(eid)
            if not e.get("target_process_key"):
                reasons.append("ptrace_target_identity_unknown:" + eid)
        if kind == "policy_denied":
            observed.setdefault("kernel_denial", []).append(eid)
    service = select_service(lineage)
    if service:
        registration = next((e for e in records if e["event_id"] == service.get("registration_event") and
            e.get("source_hook") == "raw_tp/sched_process_fork" and e.get("service_source") == 2 and
            e.get("service_process_key") == service["process_key"] and e.get("service_token") == service.get("exec_token") and
            e.get("service_exe") == service.get("exe") and e.get("service_id")), None)
        service_exec = service.get("exec_event") if rule not in {"R04", "C01"} or any(
            e["event_id"]==service.get("exec_event") for e in records) else None
        observed["service_origin"] = [service_exec or
                                     (registration["event_id"] if registration else service["process_key"])]
        if registration:
            observed["service_registration"] = [registration["event_id"]]
        if not service_exec and not registration:
            reasons.append("service_origin_snapshot_only")
    # A missing parent beyond the already observed service is not required by A.
    relevant = lineage[:lineage.index(service)+1] if service else lineage
    if any(n.get("missing") for n in relevant):
        reasons.append("ancestry_incomplete")
    earliest = min((e["monotonic_ns"] for e in records), default=0)
    latest = max((e["monotonic_ns"] for e in records), default=0)
    impacted = [x for x in loss_intervals if x["start_ns"] <= latest and x["end_ns"] >= earliest]
    if impacted:
        reasons.append("loss_in_observation_interval")
    required = REQUIREMENTS.get(rule, ())
    missing = [s for s in required if not observed.get(s)]
    reasons.extend("missing_stage:" + s for s in missing)
    reasons = list(dict.fromkeys(reasons))
    return {"requirements": list(required), "observed": observed, "missing": missing,
            "field_quality": {e["event_id"]: e.get("field_quality", {"unspecified": e.get("quality_flags", 0)}) for e in records},
            "status": "complete_for_rule" if not reasons else "reduced",
            "response_eligible": not reasons, "response_prohibited_reasons": reasons,
            "loss_intervals": impacted, "observation_start_ns": observation_start,
            "window_start_ns": earliest, "window_end_ns": latest,
            "scope": "Observed source relations and rule stages; no claim of attack causality or content read."}
