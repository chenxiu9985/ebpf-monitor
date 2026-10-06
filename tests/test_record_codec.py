import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('cc') and
                     (ROOT/'build/monitor.skel.h').exists(), 'Linux and built collector headers required')
class RecordCodecTests(unittest.TestCase):
    def test_compact_records_preserve_all_json_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory)/'codec')
            subprocess.run(['cc','-O2','-Wall','-Wextra','-Werror','-I'+str(ROOT/'build'),
                            '-I'+str(ROOT/'bpf'),str(ROOT/'tests/fixtures/record_codec.c'),
                            '-o',binary,'-lbpf','-lelf','-lz'],check=True,capture_output=True)
            def run(mode):
                return [json.loads(s) for s in subprocess.check_output([binary,mode],text=True).splitlines()]
            full, compact = run('full'), run('compact')
            self.assertEqual(len(full),10)
            # Receipt time is sampled separately in each actual encoding run.
            for record in full + compact:
                self.assertGreater(record.pop('collector_receive_ns'), 0)
            self.assertEqual(full,compact)


if __name__ == '__main__':
    unittest.main()
