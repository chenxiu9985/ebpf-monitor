"""Check real supervisor child session and foreground signal isolation."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from scripts.run_live import ROOT, supervise


@unittest.skipUnless(sys.platform.startswith('linux') and sys.version_info >= (3, 11),
                     'Linux and Python 3.11+ required')
class SupervisorTests(unittest.TestCase):
    def test_collector_keeps_auth_session_but_has_separate_signal_group(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'session'
            args = argparse.Namespace(rules=str(ROOT / 'rules/default.yaml'), out=str(output),
                                      duration=0, drain_timeout_ms=1000)
            probe = ('import os,json; print(json.dumps(dict(pid=os.getpid(),'
                     'sid=os.getsid(0),pgid=os.getpgrp())),flush=True); raise SystemExit(1)')
            with contextlib.redirect_stdout(io.StringIO()):
                result = supervise(args, collector_command=[sys.executable, '-c', probe])
            self.assertEqual(result, 1)
            child = json.loads((output / 'collector.log').read_text())
            self.assertEqual(child['sid'], os.getsid(0))
            self.assertEqual(child['pgid'], child['pid'])
            self.assertNotEqual(child['pgid'], os.getpgrp())


if __name__ == '__main__':
    unittest.main()
