import html
import json
import sqlite3
from pathlib import Path


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, time INTEGER, process TEXT, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_process ON events(process,time);
            CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, time INTEGER, rule TEXT, process TEXT, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS alerts_filter ON alerts(rule,time);
        """)
        self.pending = 0

    def event(self, e):
        cur = self.db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?)",
                              (e["event_id"], e["monotonic_ns"], e.get("process_key", ""), json.dumps(e, ensure_ascii=False)))
        self.pending += 1
        if self.pending >= 100:
            self.flush()
        return cur.rowcount == 1

    def alert(self, a):
        cur = self.db.execute("INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?)",
                              (a["alert_id"], a["monotonic_ns"], a["rule_id"], a["process_key"], json.dumps(a, ensure_ascii=False)))
        return cur.rowcount == 1

    def flush(self):
        self.db.commit()
        self.pending = 0

    def alerts(self, rule=None, process=None, since=0):
        sql, params = "SELECT body FROM alerts WHERE time>=?", [since]
        if rule:
            sql += " AND rule=?"
            params.append(rule)
        if process:
            sql += " AND process=?"
            params.append(process)
        return [json.loads(row[0]) for row in self.db.execute(sql + " ORDER BY time,id", params)]

    def evidence(self, ids):
        result = []
        for eid in ids:
            row = self.db.execute("SELECT body FROM events WHERE id=?", (eid,)).fetchone()
            result.append(json.loads(row[0]) if row else {"event_id": eid, "missing": True})
        return result

    def close(self):
        self.flush()
        self.db.close()


def report(store, destination):
    sections = []
    for alert in store.alerts():
        esc = lambda v: html.escape(str(v), quote=True)
        nodes = "".join(f"<li>{esc(n.get('exe') or '未知映像')} <code>{esc(n['process_key'])}</code></li>" for n in reversed(alert["lineage"]))
        evidence = html.escape(json.dumps(store.evidence(alert["evidence_ids"]), ensure_ascii=False, indent=2))
        sections.append(f"<article><h2>{esc(alert['rule_id'])} · {esc(alert['severity'])}</h2><p>{esc(alert['explanation'])}</p>"
                        f"<p>操作：{esc(alert['result_state'])}；处置：{esc(alert['action_state'])}；质量：{esc(alert['quality'])}</p>"
                        f"<h3>进程来源链</h3><ol>{nodes}</ol><details><summary>证据事件与时间线</summary><pre>{evidence}</pre></details></article>")
    body = "\n".join(sections) or "<p>此数据库中没有告警；这不等于没有风险。</p>"
    Path(destination).write_text("<!doctype html><html lang='zh-CN'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
                                "<title>eBPF 告警证据报告</title><style>body{max-width:1100px;margin:40px auto;padding:0 20px;font:16px/1.65 system-ui;background:#f3f5f8;color:#16243a}article{background:white;border:1px solid #d9e0e9;border-radius:12px;padding:20px;margin:18px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}code{font-size:12px;overflow-wrap:anywhere}h1{color:#174b78}</style>"
                                "<h1>eBPF 告警证据报告</h1><p>本报告展示观测证据和规则判断；风险提示不等同于攻击成功。</p>" + body + "</html>", encoding="utf-8")

