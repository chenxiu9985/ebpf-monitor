"""Write versioned schemas for the implemented interface; no dependency on network."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCHEMA=ROOT/"schema"


def schema(title, required, properties):
    return {"$schema":"https://json-schema.org/draft/2020-12/schema", "title":title,
            "type":"object", "required":required, "properties":properties}


def main():
    old=json.loads((ROOT.parent/"ebpf-monitor-v3/schema/event.schema.json").read_text())
    (SCHEMA/"event-v1.schema.json").write_text(json.dumps(old,indent=2)+"\n")
    string={"type":"string","minLength":1}
    number={"type":"integer","minimum":0}
    event=schema("eBPF monitor event v4 / schema 2",
        ["schema_version","event_id","event_type","monotonic_ns","session_id","clock_domain","source_hook"],
        {**old["properties"], "schema_version":{"const":2}, "session_id":string,
         "clock_domain":{"const":"CLOCK_MONOTONIC"}, "source_hook":string,
         "event_type":{"enum":old["properties"]["event_type"]["enum"]+["file_mapping","monitor_control"]},
         "exec_token":number,"process_start_ns":number,"collector_receive_ns":number,
         "operation_start_ns":number,"process_start_clock_domain":{"const":"CLOCK_BOOTTIME"},
         "received_ns":number,"storage_submit_ns":number,
         "field_quality":{"type":"object","additionalProperties":number},"dynamic_policy_id":number})
    event["allOf"]=[{"if":{"properties":{"event_type":{"not":{"enum":["monitor_start","monitor_health","monitor_stop","monitor_control","process_snapshot"]}}}},
                       "then":{"required":["process_key","exec_token","process_start_ns","tgid","uid"]}}]
    evidence=schema("Rule evidence quality",["requirements","observed","missing","status","response_eligible","response_prohibited_reasons"],
        {"requirements":{"type":"array","items":string},"observed":{"type":"object"},
         "missing":{"type":"array","items":string},"status":{"enum":["complete_for_rule","reduced"]},
         "response_eligible":{"type":"boolean"},"response_prohibited_reasons":{"type":"array","items":string}})
    alert=schema("v4 alert",["schema_version","alert_id","rule_id","rule_version","evidence_ids","evidence_quality"],
        {"schema_version":{"const":2},"alert_id":string,"rule_id":string,"rule_version":number,
         "evidence_ids":{"type":"array","items":string},"evidence_quality":evidence})
    control=schema("v4 control logical request; seqpacket ASCII encoding in docs",["verb","request_id","session_id","rule_version","evidence_id","tgid","start_ns","exec_token","uid","object_id","ttl_ms"],
        {"verb":{"enum":["APPLY","QUERY","REVOKE"]},"request_id":string,"session_id":string,
         "evidence_id":string,"rule_version":number,"tgid":number,"start_ns":number,
         "exec_token":number,"uid":number,"object_id":{"const":1},"ttl_ms":{"type":"integer","minimum":1,"maximum":30000}})
    control["additionalProperties"]=False
    response=schema("v4 response timeline",["request_id","state"],
        {"request_id":string,"state":{"enum":["audit","shadow","requested","applied","rejected","denied","expired","revoked","timed_out","unknown"]}})
    for name,body in (("event",event),("evidence",evidence),("alert",alert),("control",control),("response",response)):
        (SCHEMA/(name+".schema.json")).write_text(json.dumps(body,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")


if __name__=="__main__": main()
