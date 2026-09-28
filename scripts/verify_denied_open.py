"""Real unprivileged denied opens with cold user pathname and invalid pointer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.model import load_config
from monitor.runtime import doctor
from scripts.integration import stop, wait_for


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--uid', type=int, default=1000)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid <= 0:
        parser.error('requires root collector and positive non-root workload uid')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    result = {'passed': False, 'environment': doctor(), 'workload_uid': args.uid,
              'collector_sha256': hashlib.sha256((ROOT/'build/collector').read_bytes()).hexdigest()}
    try:
        with tempfile.TemporaryDirectory(prefix='v3-denied-') as tmp:
            directory = Path(tmp)
            directory.chmod(0o755)
            protected = directory/'protected.txt'
            protected.write_text('harmless fixture, never a credential')
            protected.chmod(0)
            names = directory/'pathname.bin'
            names.write_bytes(str(protected).encode()+b'\0')
            names.chmod(0o644)
            probe = directory/'probe'
            subprocess.run(['cc','-Wall','-Wextra','-Werror','-O2',
                            str(ROOT/'tests/fixtures/denied_open.c'),'-o',str(probe)],check=True)
            rules = out/'rules.json'
            rules.write_text(json.dumps({**load_config(), 'sensitive_paths':[str(protected)]}))
            session = out/'session'
            with (out/'supervisor.log').open('w') as log:
                monitor = subprocess.Popen([sys.executable,str(ROOT/'scripts/run_live.py'),str(rules),
                    '--out',str(session)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
                try:
                    wait_for(lambda: (session/'collector.log').exists() and
                             '"event_type":"monitor_start"' in (session/'collector.log').read_text(),monitor)
                    def identity():
                        os.setgroups([])
                        os.setgid(args.uid)
                        os.setuid(args.uid)
                    run = subprocess.run(['/bin/bash','-c','"$1" "$2" "$3"; rc=$?; exit "$rc"',
                        'fixture',str(probe),str(names),str(protected)],preexec_fn=identity,
                        capture_output=True,text=True)
                    result['probe_exit'] = run.returncode
                    result['probe_output'] = run.stdout
                    (out/'probe.log').write_text(run.stdout+run.stderr)
                    if run.returncode:
                        raise RuntimeError('fixture failed; inspect probe.log')
                    pid = json.loads(run.stdout)['pid']
                    monitor.send_signal(signal.SIGINT)
                    monitor.wait(timeout=20)
                finally:
                    stop(monitor)
            result['session'] = json.loads((session/'session.json').read_text())
            with sqlite3.connect(session/'alerts.db') as db:
                events = [json.loads(x[0]) for x in db.execute('select body from events')]
                alerts = [json.loads(x[0]) for x in db.execute('select body from alerts')]
            # BPF TGIDs may be host IDs when the fixture is in a PID namespace.
            keys = {e['process_key'] for e in events if e['event_type']=='process_exec'
                    and e.get('exe')==str(probe) and e.get('uid')==args.uid}
            result['namespace_pid'] = pid
            opens = [e for e in events if e.get('process_key') in keys and e['event_type']=='file_open']
            denied = [e for e in opens if e.get('path')==str(protected) and e.get('retval')==-13]
            invalid = [e for e in opens if e.get('retval')==-14]
            ids = {e['event_id'] for e in denied}
            matches = [a for a in alerts if a['rule_id']=='R01' and set(a['evidence_ids']) & ids]
            checks = {
                'unique_fixture_process':len(keys)==1,
                'two_denied_paths':len(denied)==2,
                'kernel_path_source':len(denied)==2 and all(e.get('path_source')=='kernel_filename' for e in denied),
                'cold_entry_failure_preserved':any(e.get('quality_flags',0)&2 for e in denied),
                'invalid_pointer_not_misattributed':len(invalid)==1 and invalid[0]['path']=='' and
                    invalid[0].get('path_source')=='unavailable' and
                    not any(invalid[0]['event_id'] in a['evidence_ids'] for a in alerts),
                'two_r01_alerts':len(matches)==2 and all(a['result_state']=='failed' for a in matches),
                'bash_ancestry':len(matches)==2 and all(any(n.get('exe')=='/bin/bash' for n in a['lineage'][1:]) for a in matches),
                'clean_shutdown':monitor.returncode==0 and result['session']['capture_loss_free'],
            }
            result.update(checks=checks,denied_events=denied,invalid_events=invalid,
                          alerts=matches,passed=all(checks.values()))
    finally:
        (out/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'passed':result['passed'],'checks':result.get('checks')},indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
