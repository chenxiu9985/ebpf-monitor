"""Run harmless shared Linux fixtures; never start a monitor or infer detections."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab', type=Path, default=Path('/tmp/ebpf-compare-lab'))
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--repetitions', type=int, default=30)
    a = p.parse_args()
    if a.repetitions < 1:
        p.error('repetitions must be positive')
    if os.name != 'posix':
        p.error('run this on the target Linux host')
    lab = a.lab.resolve()
    for name in ('service', 'worker', 'benign.so', 'protected.txt', 'ordinary.txt'):
        if not (lab / name).is_file():
            p.error(f'missing fixture: {lab / name}')
    a.out.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.pop('LD_PRELOAD', None)
    env.pop('LD_LIBRARY_PATH', None)
    cases = [
        ('normal_file', ['/usr/bin/cat', str(lab/'ordinary.txt')], {}, [], 'ordinary file read'),
        ('authorized_read', ['/usr/bin/cat', str(lab/'protected.txt')], {}, [], 'R01 exact executable+UID exception'),
        ('sensitive_and_failed_ptrace', [str(lab/'worker'), str(lab/'protected.txt')], {}, ['R01','R02'], 'worker opens fixture; POKEDATA targets nonexistent PID; not successful injection'),
        ('chain_a', [str(lab/'service'), str(lab/'worker'), str(lab/'protected.txt')], {}, ['R01','R02','R04','C01'], 'service -> shell -> temporary worker -> fixture open'),
        ('preload_and_chain', [str(lab/'service'), str(lab/'worker'), str(lab/'protected.txt')], {'LD_PRELOAD':str(lab/'benign.so')}, ['R01','R02','R03','R04','C01','C02'], 'environment is configured; successful mapping must be checked in monitor evidence'),
        ('authorized_preload', ['/usr/bin/true'], {'LD_PRELOAD':str(lab/'benign.so')}, [], 'R03 exact executable+UID exception'),
        ('missing_preload', ['/usr/bin/true'], {'LD_PRELOAD':str(lab/'missing.so')}, [], 'same authorized executable; loader failure boundary, not a positive alert sample'),
    ]
    failures = 0
    with a.out.open('x', encoding='utf-8') as f:
        for i in range(a.repetitions):
            for name, cmd, extra, expected, note in cases:
                start_wall = time.time_ns()
                start_mono = time.monotonic_ns()
                child = subprocess.Popen(cmd, env={**env, **extra}, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                _, stderr = child.communicate()
                row = {'case_id':f'{name}-{i+1}', 'scenario':name, 'round':i+1,
                       'pid':child.pid, 'uid':os.getuid(), 'command':cmd,
                       'start_wall_ns':start_wall, 'end_wall_ns':time.time_ns(),
                       'start_monotonic_ns':start_mono, 'end_monotonic_ns':time.monotonic_ns(),
                       'returncode':child.returncode, 'stderr':stderr,
                       'v4_candidate_rules':expected, 'note':note}
                failures += child.returncode != 0
                f.write(json.dumps(row, ensure_ascii=False)+'\n')
                f.flush()
                time.sleep(0.5)
    print(json.dumps({'scenario_runs':len(cases)*a.repetitions, 'workload_failures':failures,
                      'ground_truth':str(a.out), 'detections':'not evaluated'}))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
