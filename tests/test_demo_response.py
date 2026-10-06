import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

from scripts.demo_response import Display, cron_text, find_monitor, read_evidence, remove_job


class DemoTests(unittest.TestCase):
    def row(self, index, state, offset=0):
        return dict(phase='open', object=index, tgid=99, before_ns=1000000000+offset,
                    retval=3 if state == 'ok' else -1,
                    errno={'ok': 0, 'denied': 1, 'error': 13}[state])

    def test_actual_transitions_not_every_attempt(self):
        lines = []
        display = Display(['/a', '/b'], lines.append)
        for phase in ('ok', 'ok', 'denied', 'denied', 'ok'):
            for index in (1, 2):
                display.consume(self.row(index, phase))
        display.consume(dict(phase='existing_fd_read', retval=1))
        self.assertTrue(display.completed())
        self.assertEqual(len(lines), 7)
        self.assertIn('恢复打开', lines[-2])

    def test_no_denial_is_not_success(self):
        display = Display(['/a', '/b'], lambda _: None)
        for i in (1, 2):
            display.consume(self.row(i, 'ok'))
        display.consume(dict(phase='existing_fd_read', retval=1))
        self.assertFalse(display.completed())

    def test_dac_failure_is_not_called_blocking(self):
        lines = []
        display = Display(['/a', '/b'], lines.append)
        display.consume(self.row(1, 'error'))
        self.assertIn('errno=13', lines[0])
        self.assertIn('打开失败', lines[0])
        self.assertNotIn('打开被拒绝', lines[0])
        self.assertFalse(display.completed())

    def test_cron_retains_shell_and_guards_repeat(self):
        text = cron_text(PurePosixPath('/tmp/demo space'), [PurePosixPath('/etc/shadow'), PurePosixPath('/etc/gshadow')], 9000)
        self.assertIn('* * * * * root ', text)
        self.assertIn("/usr/bin/mkdir '/tmp/demo space/once'", text)
        self.assertIn("&& '/tmp/demo space/probe'", text)
        self.assertTrue(text.endswith('; :\n'))
        self.assertNotIn('applied', text)
        for path in ('/etc/bad%path', '/etc/bad\npath'):
            with self.assertRaises(ValueError):
                cron_text(PurePosixPath('/tmp/demo'), [PurePosixPath(path), PurePosixPath('/etc/gshadow')], 9000)

    def monitor_rows(self, root, proc, extra=False):
        rows = []
        for pid, socket in ((10, '/a.sock'), (11, '/b.sock')) if extra else ((10, '/a.sock'),):
            entry = proc / str(pid)
            entry.mkdir()
            entry.joinpath('cwd').symlink_to(root, target_is_directory=True)
            run = root / f'run-{pid}'
            run.mkdir()
            run.joinpath('rules.json').write_text(json.dumps(dict(
                response_mode='enforce', response_scope='auto', enabled=['R04'])))
            rows.append((entry, ['python3', '-m', 'monitor', 'listen', '--rules', str(run/'rules.json'), '--socket', socket], Path('/usr/bin/python3')))
            rows.append((proc/'200', ['collector', '--socket', socket], root/'build/collector'))
        # A stale directory never qualifies as a running monitor.
        (root/'stale').mkdir()
        return rows

    @unittest.skipIf(os.name != 'posix', 'real /proc cwd symlinks are Linux-only')
    def test_monitor_requires_matching_live_pair(self):
        with tempfile.TemporaryDirectory() as temp:
            root, proc = Path(temp)/'root', Path(temp)/'proc'
            root.mkdir(); proc.mkdir()
            rows = self.monitor_rows(root, proc)
            with patch('scripts.demo_response.processes', return_value=rows):
                run, _ = find_monitor(root, proc)
                self.assertEqual(run, root/'run-10')
            with patch('scripts.demo_response.processes', return_value=rows[:1]):
                with self.assertRaises(RuntimeError):
                    find_monitor(root, proc)

    @unittest.skipIf(os.name != 'posix', 'real /proc cwd symlinks are Linux-only')
    def test_ambiguous_monitors_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, proc = Path(temp)/'root', Path(temp)/'proc'
            root.mkdir(); proc.mkdir()
            rows = self.monitor_rows(root, proc, extra=True)
            with patch('scripts.demo_response.processes', return_value=rows):
                with self.assertRaises(RuntimeError):
                    find_monitor(root, proc)

    @unittest.skipIf(os.name != 'posix', 'Linux cron file replacement semantics')
    def test_cleanup_does_not_remove_replacement_job(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'job'
            path.write_text('ours')
            st = path.stat()
            identity = st.st_dev, st.st_ino
            other = Path(temp)/'other'
            other.write_text('someone else')
            other.replace(path)
            with self.assertRaises(RuntimeError):
                remove_job(path, identity)
            self.assertEqual(path.read_text(), 'someone else')
            st = path.stat()
            remove_job(path, (st.st_dev, st.st_ino))
            remove_job(path, identity)
            self.assertFalse(path.exists())

    def test_evidence_requires_same_worker_and_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp)
            exe = Path('/tmp/unique/probe')
            db = sqlite3.connect(run/'alerts.db')
            db.executescript('CREATE TABLE alerts(id,time,rule,body); CREATE TABLE responses(seq,state,body); CREATE TABLE events(time,body);')
            db.execute('INSERT INTO alerts VALUES(?,?,?,?)', ('a', 20, 'R04', json.dumps(dict(exe=str(exe)))))
            action = dict(alert_id='a', request=dict(tgid=99), exec_token=456, policy_id=7)
            db.execute('INSERT INTO responses VALUES(?,?,?)', (1, 'applied', json.dumps(action)))
            for pid, token, policy in ((99, 456, 7), (98, 456, 7), (99, 123, 7), (99, 456, 8)):
                db.execute('INSERT INTO events VALUES(?,?)', (21, json.dumps(dict(event_type='policy_denied', tgid=pid, exec_token=token, dynamic_policy_id=policy))))
            db.commit(); db.close()
            self.assertEqual(read_evidence(run, exe, 99, 10)['denied_count'], 1)
            self.assertIsNone(read_evidence(run, exe, 98, 10))
            self.assertIsNone(read_evidence(run, exe, 99, 30))


if __name__ == '__main__':
    unittest.main()
