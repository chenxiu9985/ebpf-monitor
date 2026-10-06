import json
import struct
import tempfile
import unittest
from pathlib import Path

from monitor.engine import Engine
from monitor.model import load_config, validate_event
from monitor.protocol import Decoder, encode
from monitor.runtime import Pipeline, RotatingJSONL
from monitor.scenarios import event, malicious_chain
from monitor.storage import Store, report


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(load_config())

    def run_events(self, records):
        return [a for e in records for a in self.engine.process(validate_event(e))]

    def test_chain_both_correlations(self):
        alerts = self.run_events(malicious_chain())
        self.assertEqual({a["rule_id"] for a in alerts}, {"R01", "R02", "R03", "R04", "C01", "C02"})
        c1 = next(a for a in alerts if a["rule_id"] == "C01")
        self.assertEqual(c1["evidence_ids"], ["synthetic:1", "synthetic:3", "synthetic:5", "synthetic:6"])
        self.assertEqual(c1["result_state"], "failed")

    def test_legitimate_non_sensitive_activity(self):
        self.assertEqual(self.run_events([event(1, "process_exec", exe="/usr/bin/ls"), event(2, "file_open", path="/etc/hostname")]), [])

    def test_kernel_path_recovery_preserves_failure_quality(self):
        alerts = self.run_events([
            event(1, "file_open", path="/etc/shadow", retval=-13, result_state="failed",
                  quality_flags=18, path_source="kernel_filename"),
            event(2, "file_open", path="/etc/shadow", retval=-13, result_state="failed",
                  quality_flags=16, path_source="kernel_filename"),
            event(3, "file_open", path="", retval=-14, result_state="failed",
                  quality_flags=2, path_source="unavailable")])
        self.assertEqual(len(alerts), 2)
        self.assertTrue(all(a['rule_id']=='R01' and a['result_state']=='failed' for a in alerts))
        self.assertIn('capture_fields_incomplete', alerts[0]['quality'])
        self.assertNotIn('capture_fields_incomplete', alerts[1]['quality'])

    def test_ptrace_read_is_not_write(self):
        self.assertEqual(self.run_events([event(1, "ptrace", request=1)]), [])

    def test_ptrace_failed_not_success(self):
        a = self.run_events([event(1, "ptrace", request=5, retval=-1, result_state="failed")])[0]
        self.assertEqual(a["result_state"], "failed")
        self.assertEqual(a["action_state"], "audit")

    def test_exception_requires_uid_and_exe(self):
        config = load_config()
        config["exceptions"] = [{"rule": "R02", "exe": "/usr/bin/gdb", "uid": 1000}]
        self.engine = Engine(config)
        alerts = self.run_events([event(1, "process_exec", exe="/usr/bin/gdb"), event(2, "ptrace", request=5), event(3, "ptrace", request=5, uid=1001)])
        self.assertEqual(len(alerts), 1)

    def test_root_is_not_implicitly_allowed(self):
        self.assertEqual(self.run_events([event(1, "file_open", path="/etc/shadow", uid=0)])[0]["rule_id"], "R01")

    def test_timeout_does_not_correlate(self):
        events = malicious_chain()[:5] + [event(60, "file_open", path="/etc/shadow")]
        self.assertFalse(any(a["rule_id"].startswith("C") for a in self.run_events(events)))

    def test_pid_reuse_does_not_inherit_preload(self):
        events = [event(1, "process_exec", "pid42:start1", exe="/tmp/x", env={"LD_PRELOAD": "/tmp/a.so"}),
                  event(2, "file_open", "pid42:start2", path="/etc/shadow")]
        self.assertNotIn("C02", [a["rule_id"] for a in self.run_events(events)])

    def test_old_shell_cannot_start_recent_correlation(self):
        records = malicious_chain()
        for record in records[3:]:
            record["monotonic_ns"] += 40_000_000_000
        rules = [a["rule_id"] for a in self.run_events(records)]
        self.assertIn("R04", rules)
        self.assertIn("C02", rules)
        self.assertNotIn("C01", rules)

    def test_correlation_window_includes_shell_to_open(self):
        records = malicious_chain()
        records[4]["monotonic_ns"] = 32_000_000_000
        records[5]["monotonic_ns"] = 34_000_000_000
        records[6]["monotonic_ns"] = 35_000_000_000
        rules = [a["rule_id"] for a in self.run_events(records)]
        self.assertIn("R04", rules)
        self.assertNotIn("C01", rules)

    def test_exec_replacement_clears_preload(self):
        events = [event(1, "process_exec", exe="/tmp/x", env={"LD_PRELOAD": "/tmp/a.so"}),
                  event(2, "process_exec", exe="/usr/bin/cat"), event(3, "file_open", path="/etc/shadow")]
        self.assertNotIn("C02", [a["rule_id"] for a in self.run_events(events)])

    def test_temp_prefix_boundary(self):
        events = malicious_chain()
        events[4]["exe"] = "/tmp-not-really/x"
        alerts = self.run_events(events)
        self.assertNotIn("R04", [a["rule_id"] for a in alerts])
        self.assertNotIn("C01", [a["rule_id"] for a in alerts])

    def test_loss_breaks_sequences(self):
        events = malicious_chain()[:5]
        events += [event(6, "monitor_health", metrics={"ring_lost": 1}), event(7, "file_open", path="/etc/shadow")]
        self.assertFalse(any(a["rule_id"].startswith("C") for a in self.run_events(events)))
        self.assertEqual(self.engine.loss_epoch, 1)

    def test_duplicate_id_is_ignored(self):
        e = event(1, "file_open", path="/etc/shadow")
        self.assertEqual(len(self.run_events([e, e])), 1)

    def test_missing_environment_does_not_assert_preload(self):
        self.assertEqual(self.run_events([event(1, "process_exec", exe="/bin/ls", quality_flags=8)]), [])

    def test_preload_library_not_in_temp_has_no_chain(self):
        events = [event(1, "process_exec", exe="/bin/cat", env={"LD_PRELOAD": "/opt/approved.so"}), event(2, "file_open", path="/etc/shadow")]
        rules = [a["rule_id"] for a in self.run_events(events)]
        self.assertIn("R03", rules)
        self.assertNotIn("C02", rules)

    def test_preload_config_write_intent(self):
        self.assertEqual(self.run_events([event(1, "file_open", path="/etc/ld.so.preload", flags=2)])[0]["rule_id"], "R03")
        self.assertEqual(self.run_events([event(2, "file_open", path="/etc/ld.so.preload", flags=0)]), [])

    def test_preload_config_rename(self):
        self.assertEqual(self.run_events([event(1, "file_rename", path="/tmp/x", path2="/etc/ld.so.preload")])[0]["rule_id"], "R03")

    def test_inode_alias_matches_sensitive(self):
        self.engine.sensitive_objects[(123, 456)] = "/etc/shadow"
        self.assertEqual(self.run_events([event(1, "file_open", path="/alias", device=123, inode=456)])[0]["rule_id"], "R01")

    def test_failed_exec_is_not_execution_success(self):
        self.assertEqual(self.run_events([event(1, "process_exec_failed", path="/tmp/x", env={"LD_PRELOAD": "/tmp/x.so"}, result_state="failed")]), [])

    def test_unrelated_branches_do_not_correlate(self):
        events = malicious_chain()[:5] + [event(6, "file_open", "other:1", path="/etc/shadow")]
        self.assertFalse(any(a["rule_id"].startswith("C") for a in self.run_events(events)))

    def test_disabled_rule(self):
        self.engine.config = {**self.engine.config, "enabled": []}
        self.assertEqual(self.run_events(malicious_chain()), [])

    def test_policy_denial_distinct_from_audit(self):
        a = self.run_events([event(1, "policy_denied", retval=-1, policy_version=2)])[0]
        self.assertEqual((a["action_state"], a["rule_version"]), ("denied", 2))

    def test_reload_clears_previous_chains(self):
        self.run_events(malicious_chain()[:5])
        self.engine.reload({**load_config(), "version": 2})
        self.assertEqual([a["rule_id"] for a in self.run_events([event(6, "file_open", path="/etc/shadow")])], ["R01"])

    def test_late_event_does_not_retroactively_correlate(self):
        events = malicious_chain()[:5] + [event(20, "file_open", path="/etc/hostname"), event(6, "file_open", path="/etc/shadow")]
        alerts = self.run_events(events)
        self.assertFalse(any(a["rule_id"].startswith("C") for a in alerts))
        self.assertIn("late_event", alerts[-1]["quality"])

    def test_thread_exit_does_not_expire_live_process(self):
        self.run_events([event(1, "process_exec", exe="/bin/bash"), event(2, "thread_exit", process_dead=False),
                         event(100, "file_open", "other:1", path="/tmp/x")])
        self.assertIn("worker:1", self.engine.processes)

    def test_process_exit_retained_then_expired(self):
        self.run_events([event(1, "process_exec", exe="/bin/bash"), event(2, "thread_exit", process_dead=True),
                         event(3, "file_open", "other:1", path="/tmp/x")])
        self.assertIn("worker:1", self.engine.processes)
        self.run_events([event(100, "file_open", "other:1", path="/tmp/x")])
        self.assertNotIn("worker:1", self.engine.processes)

    def test_process_cache_is_bounded(self):
        self.engine.config = {**self.engine.config, "max_processes": 2}
        self.run_events([event(i, "process_exec", f"pid:{i}", exe="/bin/true") for i in range(1, 5)])
        self.assertEqual(len(self.engine.processes), 2)
        self.assertEqual(self.engine.metrics["evicted"], 2)

    def test_parent_exec_does_not_rewrite_child_origin(self):
        records = malicious_chain()[:4]
        self.run_events(records)
        self.run_events([event(5, "process_exec", "shell:1", exe="/usr/bin/true"),
                         event(6, "process_exec", exe="/tmp/worker"),
                         event(7, "file_open", path="/etc/shadow")])
        origin = self.engine.lineage("worker:1")
        self.assertEqual(origin[1]["exe"], "/bin/bash")
        self.assertEqual(origin[1]["exec_event"], "synthetic:3")
        self.assertEqual(self.engine.lineage("shell:1")[0]["exe"], "/usr/bin/true")

    def test_parent_cache_eviction_preserves_child_evidence(self):
        self.run_events(malicious_chain()[:5])
        self.engine.processes.pop("shell:1")
        self.engine.processes.pop("service:1")
        origin = self.engine.lineage("worker:1")
        self.assertEqual(origin[1]["exec_event"], "synthetic:3")
        self.assertFalse(any(n.get("missing") for n in origin))


class InfrastructureTests(unittest.TestCase):
    def test_frames_fragmented_and_combined(self):
        e = event(1, "file_open", path="/etc/shadow")
        data = encode(e) + encode(e)
        decoder = Decoder()
        out = []
        for i in range(0, len(data), 7):
            out.extend(decoder.feed(data[i:i+7]))
        decoder.finish()
        self.assertEqual(out, [e, e])

    def test_invalid_and_truncated_frames(self):
        with self.assertRaises(ValueError):
            Decoder().feed(struct.pack("!I", 100000000))
        decoder = Decoder()
        decoder.feed(b"\x00\x00")
        with self.assertRaises(ValueError):
            decoder.finish()

    def test_schema_rejects_invalid_types(self):
        for change in ({"schema_version": 2}, {"monotonic_ns": -1}, {"uid": "root"}, {"env": []}, {"shutdown_ack_required": "true"}):
            with self.assertRaises(ValueError):
                validate_event({**event(1, "file_open"), **change})

    def test_invalid_config_does_not_replace_engine(self):
        engine = Engine(load_config())
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "rules.json"
            p.write_text('{"version":0}')
            with self.assertRaises(ValueError):
                engine.reload(load_config(p))
        self.assertEqual(engine.config["version"], 1)

    def test_pipeline_reorder_idempotency_and_html_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "test.db")
            cfg = {**load_config(), "reorder_ms": 5000}
            pipe = Pipeline(cfg, store)
            records = malicious_chain()
            for e in records[:4] + [records[5], records[4], records[6]]:
                pipe.push(e)
            pipe.flush()
            before = store.alerts()
            self.assertIn("C01", [a["rule_id"] for a in before])
            pipe2 = Pipeline(cfg, store)
            for e in records:
                pipe2.push(e)
            pipe2.flush()
            self.assertEqual(before, store.alerts())
            pipe2.push(event(10, "process_exec", "evil:1", exe="<script>alert(1)</script>"))
            pipe2.push(event(11, "file_open", "evil:1", path="/etc/shadow"))
            pipe2.flush()
            destination = Path(directory) / "report.html"
            report(store, destination)
            text = destination.read_text(encoding="utf-8")
            self.assertNotIn("<script>", text)
            self.assertIn("&lt;script&gt;", text)
            store.close()

    def test_log_rotation_preserves_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            log = RotatingJSONL(path, max_bytes=1, backups=2)
            for i in range(4):
                log.write({"index": i})
            log.close()
            self.assertEqual(json.loads(path.read_text())["index"], 3)
            self.assertEqual(json.loads(Path(str(path) + ".2").read_text())["index"], 1)

    def test_snapshot_parent_matches_exact_bpf_start(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "test.db")
            pipe = Pipeline(load_config(), store)
            pipe.push(event(1, "process_snapshot", "host:boot:10:100000000", host_id="host", boot_id="boot", tgid=10,
                            process_start_ns=100000000, snapshot_tick_ns=10000000, exe="/usr/bin/demo-service"))
            pipe.push(event(2, "process_fork", "host:boot:20:200000000", "host:boot:10:100001234", host_id="host", boot_id="boot", tgid=20, process_start_ns=200000000))
            pipe.flush()
            lineage = pipe.engine.lineage("host:boot:20:200000000")
            self.assertEqual(lineage[1]["exe"], "/usr/bin/demo-service")
            store.close()


if __name__ == "__main__":
    unittest.main()
