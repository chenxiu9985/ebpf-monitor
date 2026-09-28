import unittest

from monitor.engine import Engine
from monitor.model import load_config
from monitor.scenarios import event, malicious_chain


class ExpiryTests(unittest.TestCase):
    def test_expiry_boundary_and_changed_ttl(self):
        engine = Engine(load_config())
        engine.process(event(1, "process_exec", "dead:1", exe="/bin/true"))
        engine.process(event(2, "thread_exit", "dead:1", process_dead=True))
        engine.process(event(62, "file_open", "live:1", path="/etc/hostname"))
        self.assertIn("dead:1", engine.processes)
        engine.reload({**load_config(), "exit_retention_seconds": 100})
        engine.process(event(70, "file_open", "live:1", path="/etc/hostname"))
        self.assertIn("dead:1", engine.processes)
        engine.process(event(103, "file_open", "live:1", path="/etc/hostname"))
        self.assertNotIn("dead:1", engine.processes)

    def test_stale_expiry_cannot_delete_recreated_cache_entry(self):
        engine = Engine({**load_config(), "max_processes": 1})
        engine.process(event(1, "thread_exit", "same:1", process_dead=True))
        engine.process(event(2, "file_open", "other:1", path="/etc/hostname"))
        engine.process(event(3, "process_exec", "same:1", exe="/bin/true"))
        engine.process(event(100, "file_open", "same:1", path="/etc/hostname"))
        self.assertIn("same:1", engine.processes)

    def test_exit_heap_remains_bounded_under_eviction(self):
        engine = Engine({**load_config(), "max_processes": 2, "exit_retention_seconds": 10000})
        for i in range(1, 1000):
            engine.process(event(i, "thread_exit", f"dead:{i}", process_dead=True))
        self.assertLessEqual(len(engine.exit_heap), 68)
        self.assertLessEqual(len(engine.processes), 2)

    def test_pairing_failure_and_reconnect_break_correlations(self):
        for metric in ("unpaired", "transport_disconnects"):
            with self.subTest(metric=metric):
                engine = Engine(load_config())
                for record in malicious_chain()[:5]:
                    engine.process(record)
                engine.process(event(6, "monitor_health", metrics={metric: 1}))
                alerts = engine.process(event(7, "file_open", path="/etc/shadow"))
                self.assertEqual([a["rule_id"] for a in alerts], ["R01"])
                self.assertEqual(engine.loss_epoch, 1)


if __name__ == "__main__":
    unittest.main()
