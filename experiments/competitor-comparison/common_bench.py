"""Shared open/exec workload. Monitoring lifecycle is controlled externally."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def workload(path, opens, execs):
    started = time.perf_counter_ns()
    for _ in range(opens):
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)
    for _ in range(execs):
        subprocess.run(['/usr/bin/true'], check=True)
    return (time.perf_counter_ns()-started)/1e9


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--group', required=True)
    p.add_argument('--round', type=int, required=True)
    p.add_argument('--file', type=Path, default=Path('/tmp/ebpf-compare-lab/protected.txt'))
    p.add_argument('--opens', type=int, default=2000)
    p.add_argument('--execs', type=int, default=20)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    if min(a.round, a.opens, a.execs) < 1:
        p.error('counts and round must be positive')
    if os.name != 'posix' or not a.file.is_file():
        p.error('requires Linux and an existing fixture')
    a.out.parent.mkdir(parents=True, exist_ok=True)
    # Separate warmup PID prevents its operations being counted as measured work.
    subprocess.run(['python3', '-c', 'import os,subprocess,sys; p=sys.argv[1];\nfor _ in range(100):\n f=os.open(p,os.O_RDONLY); os.close(f)\nfor _ in range(5): subprocess.run(["/usr/bin/true"],check=True)', str(a.file)], check=True)
    row = {'group':a.group, 'round':a.round, 'pid':os.getpid(), 'uid':os.getuid(),
           'file':str(a.file.resolve()), 'opens':a.opens, 'execs':a.execs,
           'start_wall_ns':time.time_ns(), 'start_monotonic_ns':time.monotonic_ns()}
    row['seconds'] = workload(a.file, a.opens, a.execs)
    row['end_wall_ns'] = time.time_ns()
    row['end_monotonic_ns'] = time.monotonic_ns()
    row['capture_verified'] = False
    with a.out.open('x', encoding='utf-8') as f:
        json.dump(row, f, indent=2)
    print(json.dumps(row))


if __name__ == '__main__':
    main()
