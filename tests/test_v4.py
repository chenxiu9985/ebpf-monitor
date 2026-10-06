import json
import tempfile
import unittest
from pathlib import Path

from monitor.engine import Engine
from monitor.model import load_config, validate_event
from monitor.response import ResponseManager, request_bytes
from monitor.runtime import Pipeline
from monitor.scenarios import malicious_chain, event
from monitor.storage import Store


def native(record, session="test-session"):
    key = record.get("process_key", "")
    pid = {"service:1": 10, "shell:1": 20, "worker:1": 30}.get(key, 40)
    return {**record, "schema_version": 2, "session_id": session, "clock_domain": "CLOCK_MONOTONIC",
            "source_hook": "synthetic_test", "tgid": pid, "process_start_ns": pid*100,
            "exec_token": pid*1000, "device": record.get("device", 1), "inode": record.get("inode", 2)}


class V4Tests(unittest.TestCase):
    def test_stored_and_raw_event_share_exact_serialization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "events.jsonl"
            store = Store(root / "events.db")
            try:
                pipe = Pipeline(load_config(), store, raw=raw)
                record = event(1, "file_open", path="/tmp/中文文件")
                pipe.push(record)
                pipe.push(record)
                pipe.flush()
                rows = raw.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(rows), 1)
                body = store.db.execute("SELECT body FROM events").fetchone()[0]
                self.assertEqual(rows[0], body)
                self.assertEqual(json.loads(body)["path"], "/tmp/中文文件")
                self.assertEqual(pipe.engine.metrics["duplicates"], 1)
            finally:
                store.close()

    def run_chain(self, records):
        engine = Engine(load_config())
        return engine, [a for r in records for a in engine.process(validate_event(r))]

    def test_native_sequence_and_legacy_audit(self):
        _, alerts = self.run_chain([native(e) for e in malicious_chain()])
        a = next(a for a in alerts if a["rule_id"] == "R04")
        self.assertEqual(a["evidence_quality"]["status"], "complete_for_rule")
        self.assertTrue(a["evidence_quality"]["response_eligible"])
        _, old = self.run_chain(malicious_chain())
        self.assertFalse(next(a for a in old if a["rule_id"] == "R04")["evidence_quality"]["response_eligible"])

    def test_missing_mapping_never_claims_complete_c02(self):
        _, alerts = self.run_chain([native(e) for e in malicious_chain()])
        a = next(a for a in alerts if a["rule_id"] == "C02")
        self.assertIn("file_mapping_observed", a["evidence_quality"]["missing"])
        self.assertIn("object_open_observed", a["evidence_quality"]["missing"])

    def test_mapping_success_object_and_result_required(self):
        for success in (True, False):
            records = [native(e) for e in malicious_chain()[:5]]
            records += [native(event(51, "file_open", path="/tmp/demo.so", device=3, inode=4)),
                        native(event(52, "file_mapping", device=3, inode=4,
                                     result_state="succeeded" if success else "failed")),
                        native(event(53, "file_open", path="/etc/shadow"))]
            for i, r in enumerate(records):
                r["monotonic_ns"] = (i+1)*1_000_000_000
            _, alerts = self.run_chain(records)
            a = next(a for a in alerts if a["rule_id"] == "C02")
            self.assertEqual("file_mapping_observed" in a["evidence_quality"]["observed"], success)
            if success:
                self.assertEqual(a["evidence_quality"]["status"], "complete_for_rule")

    def test_exec_token_change_and_session_prevent_correlation(self):
        records = [native(e) for e in malicious_chain()[:5]]
        for changed in ({"exec_token": 9999}, {"session_id": "new-session"}):
            _, alerts = self.run_chain(records + [{**native(malicious_chain()[5]), **changed}])
            self.assertNotIn("C01", [a["rule_id"] for a in alerts])
            self.assertNotIn("C02", [a["rule_id"] for a in alerts])

    def test_shell_quality_propagates_to_precondition(self):
        records = [native(e) for e in malicious_chain()[:5]]
        records[2]["quality_flags"] = 2
        _, alerts = self.run_chain(records)
        a = next(a for a in alerts if a["rule_id"] == "R04")
        self.assertFalse(a["evidence_quality"]["response_eligible"])

    def test_r04_outside_sequence_window_cannot_request(self):
        records = [native(e) for e in malicious_chain()[:5]]
        records[-1]["monotonic_ns"] += 40_000_000_000
        _, alerts = self.run_chain(records)
        a = next(a for a in alerts if a["rule_id"] == "R04")
        self.assertIn("sequence_window_expired", a["evidence_quality"]["response_prohibited_reasons"])

    def test_failed_exec_and_non_service_do_not_arm(self):
        for change in ((0, {"exe": "/usr/bin/normal"}), (2, {"event_type": "process_exec_failed", "result_state": "failed"})):
            records = [native(e) for e in malicious_chain()]
            records[change[0]].update(change[1])
            _, alerts = self.run_chain(records)
            self.assertNotIn("R04", [a["rule_id"] for a in alerts])
            self.assertNotIn("C01", [a["rule_id"] for a in alerts])

    def test_loss_and_late_block_response(self):
        records = [native(e) for e in malicious_chain()[:4]]
        loss = native(event(45, "monitor_health", metrics={"ring_lost": 1}))
        loss["monotonic_ns"] = 4_500_000_000
        _, alerts = self.run_chain(records + [loss, native(malicious_chain()[4])])
        self.assertFalse(next(a for a in alerts if a["rule_id"] == "R04")["evidence_quality"]["response_eligible"])

    def test_response_shadow_replay_and_ambiguous_ack(self):
        e = native(malicious_chain()[4])
        _, alerts = self.run_chain([native(r) for r in malicious_chain()[:5]])
        a = next(a for a in alerts if a["rule_id"] == "R04")
        class Client:
            def __init__(self): self.verbs = []
            def exchange(self, request):
                self.verbs.append(request["verb"])
                if request["verb"] == "APPLY": raise TimeoutError()
                return {"request_id": request["request_id"], "state": "applied", "policy_id": 1}
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp)/"db")
            client = Client()
            cfg = {**load_config(), "response_mode": "enforce", "response_scope": "legacy"}
            ResponseManager(cfg, store, live=False, client=client).consider(a, e)
            self.assertEqual(client.verbs, [])
            self.assertIn("offline_replay", store.responses()[-1]["reasons"])
            ResponseManager({**cfg, "response_mode": "shadow"}, store, live=True, client=client).consider(a, e)
            self.assertEqual(store.responses()[-1]["state"], "shadow")
            self.assertEqual(client.verbs, [])
            ResponseManager(cfg, store, live=True, client=client).consider(a, e)
            self.assertEqual(client.verbs, ["APPLY", "QUERY"])
            self.assertEqual([r["state"] for r in store.responses()][-3:], ["requested", "timed_out", "applied"])
            store.close()

    def test_repeat_replay_does_not_duplicate_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp)/"db")
            cfg = {**load_config(), "response_mode": "shadow"}
            for _ in range(2):
                pipe = Pipeline(cfg, store)
                for e in malicious_chain(): pipe.push(native(e))
                pipe.flush()
            self.assertEqual(len(store.responses()), 1)
            store.close()

    def test_control_rejects_arbitrary_fields_or_strings(self):
        request = dict(verb="APPLY", request_id="abc", session_id="session", rule_version=1, evidence_id="def",
                       tgid=3, start_ns=4, exec_token=5, uid=1000, object_id=1, ttl_ms=100)
        self.assertTrue(request_bytes(request).startswith(b"V4 1 APPLY"))
        for changes in ({"object_id": 2}, {"ttl_ms": 30001}, {"request_id": "x\nAPPLY"}, {"uid": True}, {"path": "/etc/shadow"}):
            with self.assertRaises(ValueError): request_bytes({**request, **changes})

    def test_schema_clock_and_missing_identity_rejected(self):
        record = native(event(1, "process_exec"))
        for changes in ({"schema_version": 3}, {"exec_token": -1}, {"clock_domain": "wall"}, {"session_id": ""}, {"operation_start_ns": "bad"}):
            with self.assertRaises(ValueError): validate_event({**record, **changes})
        del record["exec_token"]
        with self.assertRaises(ValueError): validate_event(record)

    def test_filter_equivalence_with_reordering_and_loading(self):
        from scripts.equivalence import run
        records=[native(e) for e in malicious_chain()]
        records += [native(event(8,"file_open","other:1",path="/etc/hostname")),
                    native(event(9,"file_open",path="/tmp/demo.so"))]
        records[4],records[5]=records[5],records[4]
        with tempfile.TemporaryDirectory() as directory:
            config={**load_config(),"reorder_ms":5000}
            full=run(records,config,Path(directory),"full")
            filtered=run(records,config,Path(directory),"rule_related")
            self.assertEqual(full["alerts"],filtered["alerts"])
            self.assertEqual(filtered["filtered"],1)

    def test_application_interval_is_not_syscall_exit_time(self):
        from monitor.storage import classify_operation
        action={"update_before_ns":100,"update_after_ns":120,"expires_ns":200}
        self.assertEqual(classify_operation({"operation_start_ns":90,"monotonic_ns":130},action),"application_boundary_uncertain")
        self.assertEqual(classify_operation({"operation_start_ns":121,"monotonic_ns":150},action),"after_application")
        self.assertEqual(classify_operation({"operation_start_ns":201,"monotonic_ns":210},action),"after_expiry")
        self.assertEqual(classify_operation({"monotonic_ns":130},action),"unknown_operation_start")

    def test_denial_context_does_not_cross_collector_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory)/"db")
            store.response({"request_id":"old","state":"applied","policy_id":1,"alert_id":"old-alert","request":{"session_id":"old-session"}})
            store.response({"request_id":"new","state":"applied","policy_id":1,"alert_id":"new-alert","request":{"session_id":"new-session"}})
            ResponseManager(load_config(),store).denial({"event_type":"policy_denied","dynamic_policy_id":1,"session_id":"old-session","event_id":"denial","monotonic_ns":1})
            self.assertEqual(store.responses()[-1]["alert_id"],"old-alert")
            store.close()

    def test_control_lifecycle_does_not_reset_loss_counter_baseline(self):
        records=[native(event(1,"monitor_health",metrics={"ring_lost":1})),
                 native(event(2,"monitor_control",state="applied",request_id="one")),
                 native(event(3,"monitor_health",metrics={"ring_lost":1}))]
        engine,_=self.run_chain(records)
        self.assertEqual(engine.loss_epoch,1)
        with self.assertRaises(ValueError): validate_event(native(event(4,"monitor_health",metrics={"ring_lost":-1})))


if __name__ == "__main__":
    unittest.main()
