"""One-command workload for an already running automatic-response monitor.

Uses the existing cron service, never launches a monitor or edits its policy.
The worker starts opening immediately; response confirmation is read afterwards.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import errno
import json
import os
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def option(args, name):
    try:
        return args[args.index(name) + 1]
    except (ValueError, IndexError):
        return None


def processes(proc=Path('/proc')):
    result = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = entry.joinpath('cmdline').read_bytes().decode().rstrip('\0').split('\0')
            result.append((entry, argv, entry.joinpath('exe').resolve()))
        except (OSError, UnicodeError, RuntimeError):
            continue
    return result


def find_monitor(root=ROOT, proc=Path('/proc')):
    rows = processes(proc)
    collectors = [args for _, args, exe in rows if exe == root / 'build/collector']
    candidates = []
    for entry, args, _ in rows:
        if ['-m', 'monitor', 'listen'] != args[1:4]:
            continue
        try:
            if entry.joinpath('cwd').resolve() != root:
                continue
        except OSError:
            continue
        rules, socket = option(args, '--rules'), option(args, '--socket')
        if rules and socket and any(option(c, '--socket') == socket for c in collectors):
            candidates.append(Path(rules).resolve().parent)
    if len(candidates) != 1:
        raise RuntimeError('需要且只能有一个本项目的实时监控进程；请先在左侧启动 run_live.py。')
    run = candidates[0]
    config = json.loads((run / 'rules.json').read_text(encoding='utf-8'))
    if config.get('response_mode') != 'enforce' or config.get('response_scope') != 'auto':
        raise RuntimeError('左侧监控需要 --response-mode enforce，并使用自动响应范围。')
    if 'R04' not in config.get('enabled', []):
        raise RuntimeError('本次监控没有启用 R04。')
    return run, config


def check_cron(config):
    value = subprocess.check_output(
        ['systemctl', 'show', 'cron.service', '-p', 'MainPID', '--value'], text=True).strip()
    if not value.isdigit() or int(value) <= 0:
        raise RuntimeError('cron.service 没有运行。')
    exe = Path('/proc') / value / 'exe'
    if not any(Path(p).exists() and os.path.samefile(exe, p)
               for p in config.get('service_executables', [])):
        raise RuntimeError('当前 cron 程序不在本次监控的 service_executables 中。')


def cron_text(lab, objects, duration):
    parts = [str(lab / 'probe'), *map(str, objects), str(duration)]
    if any('%' in p or '\n' in p or '\r' in p for p in parts):
        raise ValueError('演示路径不能包含 cron 的百分号或换行字符。')
    return ('SHELL=/bin/sh\nPATH=/usr/bin:/bin\n'
            '* * * * * root /usr/bin/mkdir ' + shlex.quote(str(lab / 'once'))
            + ' 2>/dev/null && ' + shlex.join(parts) + ' > '
            + shlex.quote(str(lab / 'worker.jsonl')) + ' 2>&1; :\n')


class Display:
    def __init__(self, objects, emit=print):
        self.objects, self.emit = objects, emit
        self.begin = None
        self.states = {}
        self.history = {1: [], 2: []}
        self.pid = None
        self.done = False

    def consume(self, row):
        if row['phase'] == 'existing_fd_read':
            self.done = True
            self.emit(f"已打开的 fd 仍可读取：{row['retval']} 字节（不显示文件内容）。")
            return
        if row['phase'] != 'open':
            return
        self.pid = row['tgid']
        if self.begin is None:
            self.begin = row['before_ns']
        index = row['object']
        state = 'ok' if row['retval'] >= 0 else ('denied' if row['errno'] == errno.EPERM else 'error')
        if self.states.get(index) == state:
            return
        previous = self.states.get(index)
        self.states[index] = state
        self.history[index].append(state)
        elapsed = (row['before_ns'] - self.begin) / 1e9
        if state == 'ok':
            message = '恢复打开' if previous == 'denied' else '打开成功'
            detail = f"fd={row['retval']}"
        else:
            message = '打开被拒绝' if state == 'denied' else '打开失败'
            detail = f"errno={row['errno']}，{os.strerror(row['errno'])}"
        self.emit(f"[{elapsed:5.2f}s] {self.objects[index-1]}：{message}（{detail}）")

    def completed(self):
        return self.done and all(h == ['ok', 'denied', 'ok'] for h in self.history.values())


def read_evidence(run, exe, pid, since):
    with closing(sqlite3.connect((run / 'alerts.db').as_uri() + '?mode=ro', uri=True, timeout=1)) as db:
        row = db.execute("""SELECT r.body FROM responses r JOIN alerts a
            ON a.id=json_extract(r.body,'$.alert_id')
            WHERE r.state='applied' AND a.rule='R04' AND a.time>=?
            AND json_extract(a.body,'$.exe')=?
            AND coalesce(json_extract(r.body,'$.tgid'),json_extract(r.body,'$.request.tgid'))=?
            ORDER BY r.seq DESC LIMIT 1""", (since, str(exe), pid)).fetchone()
        if not row:
            return None
        action = json.loads(row[0])
        count = db.execute("""SELECT count(*) FROM events WHERE time>=?
            AND json_extract(body,'$.event_type')='policy_denied'
            AND json_extract(body,'$.tgid')=?
            AND json_extract(body,'$.exec_token')=?
            AND json_extract(body,'$.dynamic_policy_id')=?""",
            (since, pid, action['exec_token'], action['policy_id'])).fetchone()[0]
        return dict(rule_id='R04', policy_id=action['policy_id'],
                    exec_token=action['exec_token'], tgid=pid, denied_count=count)


def remove_job(path, identity):
    try:
        st = path.stat()
    except FileNotFoundError:
        return
    if (st.st_dev, st.st_ino) != identity:
        raise RuntimeError(f'定时任务文件已被替换，未删除：{path}')
    path.unlink()


def demonstrate():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('请在 Ubuntu 使用 sudo python3 scripts/demo_response.py。')
    if not shutil.which('cc'):
        raise RuntimeError('没有 cc 编译器；请先安装项目构建依赖。')
    run, config = find_monitor()
    check_cron(config)
    objects = [Path('/etc/shadow'), Path('/etc/gshadow')]
    configured = [Path(p) for p in config.get('sensitive_paths', []) if Path(p).exists()]
    if not all(p.is_file() and any(os.path.samefile(p, q) for q in configured) for p in objects):
        raise RuntimeError('本演示需要本次监控已保护 /etc/shadow 和 /etc/gshadow（默认配置）。')
    log = run / 'collector.log'
    if not log.exists() or '"event_type":"monitor_start"' not in log.read_text(errors='replace'):
        raise RuntimeError('采集器尚未就绪；请稍后重试。')
    if not (run / 'alerts.db').is_file():
        raise RuntimeError('本次监控数据库尚未就绪。')
    duration = int(config['response_ttl_ms']) + max(4000, int(config.get('reorder_ms', 200)) + 2000)
    lab = Path(tempfile.mkdtemp(prefix='ebpf-r04-demo.', dir='/tmp'))
    # Keep the real worker output and binary for inspection; only our cron job is removed.
    subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(ROOT / 'tests/fixtures/auto_response_worker.c'), '-o', str(lab / 'probe')], check=True)
    job = Path('/etc/cron.d') / ('ebpf-r04-demo-' + lab.name.rsplit('.', 1)[1])
    since = time.monotonic_ns()
    display = Display(objects, lambda line: print(line, flush=True))
    with job.open('x', encoding='utf-8', newline='\n') as stream:
        os.chmod(job, 0o644)
        identity = (os.fstat(stream.fileno()).st_dev, os.fstat(stream.fileno()).st_ino)
        try:
            stream.write(cron_text(lab, objects, duration))
            stream.flush()
        except BaseException:
            remove_job(job, identity)
            raise
    try:
        print('执行链：cron.service → /bin/sh → /tmp/临时程序', flush=True)
        print('等待 cron 的下一次分钟调度；开始后连续访问，不等待策略确认。', flush=True)
        print(f'监控记录：{run}\n程序记录：{lab}/worker.jsonl', flush=True)
        worker_log = lab / 'worker.jsonl'
        deadline = time.monotonic() + 95
        offset, pending = 0, ''
        while not display.done:
            if time.monotonic() >= deadline:
                raise RuntimeError('未在预期时间完成；请检查 cron 状态和程序记录。')
            if worker_log.exists():
                with worker_log.open(encoding='utf-8') as stream:
                    stream.seek(offset)
                    pending += stream.read()
                    offset = stream.tell()
                while '\n' in pending:
                    line, pending = pending.split('\n', 1)
                    row = json.loads(line)
                    first = display.begin is None
                    display.consume(row)
                    if first and display.begin is not None:
                        deadline = time.monotonic() + duration / 1000 + 10
            time.sleep(0.05)
        evidence = None
        until = time.monotonic() + 3
        while time.monotonic() < until:
            evidence = read_evidence(run, lab / 'probe', display.pid, since)
            if evidence and evidence['denied_count']:
                break
            time.sleep(0.1)
        passed = display.completed() and bool(evidence and evidence['denied_count'])
        summary = dict(passed=passed, monitor_output=str(run), worker_output=str(worker_log),
                       transitions=display.history, evidence=evidence)
        (lab / 'result.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
        if not passed:
            raise RuntimeError('未验证完整响应；查看上述记录。不会将普通访问失败当作 LSM 阻断。')
        print(f"R04 已核实；策略 {evidence['policy_id']}；内核实际拒绝 {evidence['denied_count']} 次。", flush=True)
        print('演示完成，定时任务自动移除；左侧监控继续运行。', flush=True)
    finally:
        remove_job(job, identity)


def main():
    argparse.ArgumentParser(description='右侧一条命令：已有 cron 服务触发 R04，展示真实阻断与到期恢复。').parse_args()
    def terminate(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    try:
        demonstrate()
        return 0
    except KeyboardInterrupt:
        print('\n演示停止；已移除定时任务。已启动的程序会在有限时长内自行退出。', file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.CalledProcessError) as exc:
        print(f'演示未完成：{exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
