"""Alternate unmonitored and complete live monitoring on the same open/exec workload."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from monitor.runtime import doctor
from scripts.benchmark import workload, collector_cpu
from scripts.integration import stop, wait_for


def rss(pid):
    return next(int(line.split()[1]) for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                if line.startswith('VmRSS:'))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--rounds', type=int, default=5)
    p.add_argument('--opens', type=int, default=10000)
    p.add_argument('--execs', type=int, default=100)
    p.add_argument('--environment-label', default='unspecified')
    args = p.parse_args()
    if os.geteuid()!=0 or min(args.rounds,args.opens,args.execs)<1:
        p.error('root and positive workload counts required')
    out = args.out.resolve()
    out.mkdir(parents=True,exist_ok=False)
    result = {'source':'FULL_LIVE_MICROBENCHMARK','environment':doctor(),
              'parameters':{**vars(args),'out':str(out)},'rounds':[], 'completed':False,
              'group_definitions':{'B0':'no collector or analyzer','B3':'collector + rules + JSONL + SQLite'},
              'limitations':['Open/exec-intensive synthetic workload; not representative application overhead.',
                             'RSS is an end-of-workload sample, not peak or total kernel memory.',
                             'CPU covers the two userspace processes during workload, not all system CPU.'],
              'source_sha256':{str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest()
                 for directory in ['bpf','collector','monitor','scripts','rules']
                 for f in sorted((ROOT/directory).rglob('*')) if f.is_file() and '__pycache__' not in f.parts}}
    result['source_sha256']['build/collector']=hashlib.sha256((ROOT/'build/collector').read_bytes()).hexdigest()
    try:
        with tempfile.TemporaryDirectory(prefix='v3-live-bench-') as tmp:
            fixture = Path(tmp)/'file'
            fixture.write_text('harmless benchmark data')
            workload(fixture,100,5)
            for i in range(args.rounds):
                for group in (['B0','B3'] if i%2==0 else ['B3','B0']):
                    row = {'round':i+1,'group':group}
                    process = None
                    log = None
                    started = None
                    try:
                        if group=='B3':
                            session = out/f'round-{i+1}'
                            logpath = out/f'round-{i+1}-supervisor.log'
                            log = logpath.open('w')
                            process = subprocess.Popen([sys.executable,str(ROOT/'scripts/run_live.py'),
                                '--out',str(session)],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
                            wait_for(lambda: (session/'collector.log').exists() and
                                '"event_type":"monitor_start"' in (session/'collector.log').read_text(),process)
                            def ids():
                                for line in logpath.read_text().splitlines():
                                    try:
                                        value=json.loads(line)
                                        if 'collector_pid' in value: return value
                                    except ValueError: pass
                                return None
                            wait_for(lambda: ids() is not None,process)
                            children=ids()
                            before={name:collector_cpu(pid) for name,pid in children.items()}
                        started=time.perf_counter()
                        row['seconds']=workload(fixture,args.opens,args.execs)
                        if process:
                            row['cpu_seconds_during_workload']={name:collector_cpu(pid)-before[name] for name,pid in children.items()}
                            row['rss_kib_at_workload_end']={name:rss(pid) for name,pid in children.items()}
                            process.send_signal(signal.SIGINT)
                            process.wait(timeout=20)
                        row['completion_seconds']=time.perf_counter()-started
                        row['drain_and_shutdown_seconds']=row['completion_seconds']-row['seconds']
                        if process:
                            status=json.loads((session/'session.json').read_text())
                            row['session']=status
                            with sqlite3.connect(session/'alerts.db') as db:
                                captured=db.execute("SELECT COUNT(*) FROM events WHERE json_extract(body,'$.event_type')='file_open' AND json_extract(body,'$.path')=?",(str(fixture),)).fetchone()[0]
                            row['captured_fixture_opens']=captured
                            row['passed']=process.returncode==0 and status['capture_loss_free'] and captured==args.opens
                        else: row['passed']=True
                    finally:
                        stop(process)
                        if log: log.close()
                    result['rounds'].append(row)
                    (out/'result.json').write_text(json.dumps(result,indent=2))
                    print(json.dumps({k:v for k,v in row.items() if k!='session'}),flush=True)
        result['median_seconds']={g:statistics.median(r['seconds'] for r in result['rounds'] if r['group']==g) for g in ['B0','B3']}
        b0,b3=(result['median_seconds'][g] for g in ['B0','B3'])
        result.update(completed=True,passed=all(r['passed'] for r in result['rounds']),
                      elapsed_increase_percent=100*(b3/b0-1),throughput_drop_percent=100*(1-b0/b3))
        result['overhead_valid_for_complete_capture'] = result['passed']
        if not result['passed']:
            result['interpretation'] = 'Capture incomplete: timing ratios do not establish loss-free monitoring overhead.'
    finally:
        (out/'result.json').write_text(json.dumps(result,indent=2))
    print(json.dumps({k:result[k] for k in ['passed','median_seconds','elapsed_increase_percent','throughput_drop_percent']},indent=2))
    return 0 if result['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
