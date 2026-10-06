import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from monitor.assets import write_manifest
from monitor.engine import Engine
from monitor.model import load_config, validate_event
from monitor.response import ControlClient, ResponseManager, request_bytes
from monitor.storage import Store

ROOT = Path(__file__).resolve().parents[1]


def record(seq, kind, key, parent="", **fields):
    return dict(schema_version=2, event_id=str(seq), event_type=kind, process_key=key,
                parent_process_key=parent, monotonic_ns=seq*1_000_000, session_id="auto-test",
                clock_domain="CLOCK_MONOTONIC", source_hook="raw_tp/sched_process_fork" if kind=="process_fork" else "sched/sched_process_exec",
                exec_token=seq+100, tgid=seq, process_start_ns=seq*100, uid=1000,
                cgroup_id=789, result_state="succeeded", **fields)


def chain(existing=False, helper=False):
    rows=[]
    if not existing:
        rows.append(record(1,"process_exec","service",exe="/usr/sbin/cron"))
    source=dict(service_id=1, service_source=2, service_token=800, service_start_ns=90,
                service_process_key="service", service_exe="/usr/sbin/cron") if existing else {}
    parent="service"
    if helper:
        rows.append(record(2,"process_fork","helper","service",**source))
        parent="helper"
    rows.append(record(3,"process_fork","shell",parent,**source))
    rows.append(record(4,"process_exec","shell",parent,exe="/bin/sh"))
    rows.append(record(5,"process_fork","worker","shell"))
    rows.append(record(6,"process_exec","worker","shell",exe="/tmp/probe",service_id=1))
    return rows


class AutoAnalysisTests(unittest.TestCase):
    def alerts(self, rows):
        engine=Engine(load_config())
        return [a for e in rows for a in engine.process(validate_event(e))]

    def test_observed_service_survives_cron_helper_without_forging_exec(self):
        alert=next(a for a in self.alerts(chain(helper=True)) if a["rule_id"]=="R04")
        self.assertTrue(alert["evidence_quality"]["response_eligible"])
        self.assertIn("2",alert["evidence_ids"])
        helper=next(n for n in alert["lineage"] if n["process_key"]=="helper")
        self.assertEqual(helper["exec_event"],"")

    def test_existing_service_requires_native_registration_not_snapshot(self):
        rows=chain(existing=True,helper=True)
        alert=next(a for a in self.alerts(rows) if a["rule_id"]=="R04")
        self.assertTrue(alert["evidence_quality"]["response_eligible"])
        self.assertIn("service_registration",alert["stages"])
        service=next(n for n in alert["lineage"] if n["process_key"]=="service")
        self.assertEqual(service["exec_event"],"")
        for e in rows:
            e["source_hook"]="synthetic_untrusted"
        rows.insert(0,record(1,"process_snapshot","service",exe="/usr/sbin/cron"))
        alert=next(a for a in self.alerts(rows) if a["rule_id"]=="R04")
        self.assertFalse(alert["evidence_quality"]["response_eligible"])
        self.assertIn("service_origin_snapshot_only",alert["evidence_quality"]["response_prohibited_reasons"])

    def test_incomplete_registration_receipt_vetoes_response(self):
        rows=chain(existing=True)
        rows[0]["quality_flags"]=4
        alert=next(a for a in self.alerts(rows) if a["rule_id"]=="R04")
        self.assertFalse(alert["evidence_quality"]["response_eligible"])

    def test_live_kernel_receipt_refreshes_proof_after_raw_service_exec_eviction(self):
        rows=chain(helper=True)
        proof=dict(service_id=1,service_source=2,service_token=101,service_start_ns=100,
                   service_process_key="service",service_exe="/usr/sbin/cron")
        rows[1].update(proof); rows[2].update(proof)
        engine=Engine(load_config())
        for e in rows[:2]: engine.process(validate_event(e))
        engine.records.clear()  # the old service exec and first fork aged out
        alerts=[a for e in rows[2:] for a in engine.process(validate_event(e))]
        alert=next(a for a in alerts if a["rule_id"]=="R04")
        # Helper's fork is still required: a missing raw helper proof must veto.
        self.assertFalse(alert["evidence_quality"]["response_eligible"])
        engine=Engine(load_config())
        for e in rows[:2]: engine.process(validate_event(e))
        del engine.records["1"]
        alerts=[a for e in rows[2:] for a in engine.process(validate_event(e))]
        alert=next(a for a in alerts if a["rule_id"]=="R04")
        self.assertTrue(alert["evidence_quality"]["response_eligible"])
        self.assertIn("3",alert["stages"]["service_registration"])

    def test_automatic_request_uses_observed_uid_cgroup_and_object_set(self):
        rows=chain()
        alert=next(a for a in self.alerts(rows) if a["rule_id"]=="R04")
        class Client:
            def exchange(self, request):
                self.request=request
                return dict(state="applied",policy_id=1)
        client=Client()
        with tempfile.TemporaryDirectory() as temporary:
            store=Store(Path(temporary)/"db")
            try:
                cfg={**load_config(),"response_mode":"enforce"}
                ResponseManager(cfg,store,live=True,client=client).consider(alert,rows[-1])
                self.assertEqual(client.request["cgroup_id"],789)
                self.assertEqual(client.request["uid"],1000)
                self.assertEqual(client.request["object_id"],0)
                self.assertTrue(request_bytes(client.request).startswith(b"V4 2 "))
            finally:
                store.close()

    def test_manifest_is_bounded_and_rejects_control_characters(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"assets"
            cfg=load_config()
            write_manifest(cfg,path)
            self.assertIn("object\t1\t/etc/shadow",path.read_text())
            for bad in ([],["/tmp/x\nservice\t1\t/evil"],["/tmp/"+"x"*256]):
                with self.assertRaises(ValueError):
                    write_manifest({**cfg,"sensitive_paths":bad},path)


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc"),"Linux control handler")
class AutoControlTests(unittest.TestCase):
    def test_runtime_scope_multi_object_refresh_and_missing_service(self):
        for no_service in (False,True):
            with self.subTest(no_service=no_service), tempfile.TemporaryDirectory() as temporary:
                temp=Path(temporary); obj=temp/"object"; second=temp/"second"
                obj.write_text("safe"); second.write_text("safe")
                alias=temp/"alias"; os.link(obj,alias)
                manifest=temp/"assets"
                write_manifest({**load_config(),"sensitive_paths":[str(obj),str(second),str(alias)],
                                "service_executables":["/bin/sh"]},manifest)
                binary=temp/"server"; endpoint=temp/"control.sock"
                subprocess.run(["cc","-Wall","-Wextra","-Werror","-I"+str(ROOT/"bpf"),
                                str(ROOT/"tests/fixtures/control_mock.c"),"-o",str(binary)],check=True,capture_output=True)
                env={**os.environ,"AUTO_MANIFEST":str(manifest)}
                if no_service: env["MOCK_NO_SERVICE"]="1"
                with (temp/"registry.log").open("w") as log:
                    child=subprocess.Popen([str(binary),str(endpoint),str(obj)],env=env,stderr=log)
                    try:
                        until=time.monotonic()+3
                        while not endpoint.exists():
                            self.assertIsNone(child.poll())
                            if time.monotonic()>until: self.fail("control startup timeout")
                            time.sleep(.01)
                        client=ControlClient(str(endpoint))
                        req=dict(verb="APPLY",request_id="auto",session_id="test-session",rule_version=1,
                                 evidence_id="proof",tgid=42,start_ns=100,exec_token=900,uid=1000,
                                 object_id=0,ttl_ms=3000,cgroup_id=789)
                        reply=client.exchange(req)
                        self.assertEqual(reply["state"],"rejected" if no_service else "applied")
                        if no_service:
                            self.assertEqual(reply["reason"],"runtime_scope_or_service")
                            continue
                        self.assertEqual(reply["cgroup_id"],789)
                        self.assertEqual(client.exchange({**req,"verb":"REVOKE"})["state"],"revoked")
                        for changes in ({"uid":0},{"cgroup_id":790},{"exec_token":901}):
                            self.assertEqual(client.exchange({**req,**changes,"request_id":str(list(changes)[0])})["state"],"rejected")
                        replacement=temp/"replacement"; replacement.write_text("updated")
                        replacement.replace(obj)
                        time.sleep(.35)
                        reply=client.exchange({**req,"request_id":"replacement"})
                        self.assertEqual(reply["state"],"applied")
                        self.assertEqual(client.exchange({**req,"request_id":"replacement","verb":"REVOKE"})["state"],"revoked")
                        obj.unlink(); second.unlink(); alias.unlink(); time.sleep(.35)
                        self.assertEqual(client.exchange({**req,"request_id":"empty"})["reason"],"runtime_scope_or_service")
                        second.write_text("restored"); time.sleep(.35)
                        self.assertEqual(client.exchange({**req,"request_id":"restored"})["state"],"applied")
                    finally:
                        child.terminate(); child.wait(timeout=3)
                logs=[json.loads(line) for line in (temp/"registry.log").read_text().splitlines()]
                current=next(r for r in reversed(logs) if r["event_type"]=="monitor_registry")
                self.assertEqual(sum(o["active"] for o in current["objects"]),1)
