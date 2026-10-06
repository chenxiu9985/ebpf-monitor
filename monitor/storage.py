import html
import json
import sqlite3
import time
from pathlib import Path


class Store:
    def __init__(self, path, batch_size=500, commit_interval_ms=250):
        if type(batch_size) is not int or not 1 <= batch_size <= 5000:
            raise ValueError("invalid storage batch size")
        if type(commit_interval_ms) is not int or not 1 <= commit_interval_ms <= 1000:
            raise ValueError("invalid commit interval")
        self.batch_size = batch_size
        self.commit_interval_ns = commit_interval_ms*1_000_000
        self.last_commit_ns = time.monotonic_ns()
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, time INTEGER, process TEXT, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_process ON events(process,time);
            CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, time INTEGER, rule TEXT, process TEXT, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS alerts_filter ON alerts(rule,time);
            CREATE TABLE IF NOT EXISTS responses(seq INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, state TEXT, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS responses_request ON responses(request_id,seq);
            CREATE INDEX IF NOT EXISTS responses_policy ON responses(json_extract(body,'$.policy_id'),coalesce(json_extract(body,'$.session_id'),json_extract(body,'$.request.session_id')),seq);
        """)
        self.pending = 0

    def response(self, record):
        self.db.execute("INSERT INTO responses(request_id,state,body) VALUES(?,?,?)",
                        (record["request_id"], record["state"], json.dumps(record, ensure_ascii=False)))

    def responses(self):
        return [json.loads(r[0]) for r in self.db.execute("SELECT body FROM responses ORDER BY seq")]

    def response_context(self, request_id=None, policy_id=None, session_id=None):
        if request_id is not None:
            sql="SELECT body FROM responses WHERE request_id=? AND json_extract(body,'$.alert_id') IS NOT NULL ORDER BY seq DESC LIMIT 1"
            params=(request_id,)
        else:
            sql="SELECT body FROM responses WHERE json_extract(body,'$.policy_id')=? AND coalesce(json_extract(body,'$.session_id'),json_extract(body,'$.request.session_id'))=? AND json_extract(body,'$.alert_id') IS NOT NULL ORDER BY seq DESC LIMIT 1"
            params=(policy_id,session_id)
        row=self.db.execute(sql,params).fetchone()
        return json.loads(row[0]) if row else {}

    def event(self, e):
        inserted, _ = self.event_with_body(e)
        return inserted

    def event_with_body(self, e):
        e["storage_submit_ns"] = time.monotonic_ns()
        body = json.dumps(e, ensure_ascii=False, separators=(",", ":"))
        cur = self.db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?)",
                              (e["event_id"], e["monotonic_ns"], e.get("process_key", ""), body))
        self.pending += 1
        if self.pending >= self.batch_size or time.monotonic_ns()-self.last_commit_ns >= self.commit_interval_ns:
            self.flush()
        return cur.rowcount == 1, body

    def alert(self, a):
        a["storage_submit_ns"] = time.monotonic_ns()
        cur = self.db.execute("INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?)",
                              (a["alert_id"], a["monotonic_ns"], a["rule_id"], a["process_key"], json.dumps(a, ensure_ascii=False)))
        return cur.rowcount == 1

    def flush(self):
        self.db.commit()
        self.pending = 0
        self.last_commit_ns = time.monotonic_ns()

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
    responses = store.responses()
    for alert in store.alerts():
        esc = lambda v: html.escape(str(v), quote=True)
        nodes = "".join(f"<li>{esc(n.get('exe') or '未知映像')} <code>{esc(n['process_key'])}</code></li>" for n in reversed(alert["lineage"]))
        facts = store.evidence(alert["evidence_ids"])
        related_ids = {r["request_id"] for r in responses if r.get("process_key") == alert["process_key"] and r.get("exec_token") == alert.get("exec_token")}
        action_rows = [r for r in responses if r.get("alert_id") == alert["alert_id"] or r["request_id"] in related_ids]
        applied = [r for r in action_rows if r["state"] == "applied" and r.get("request")]
        for e in facts:
            for action in applied:
                request = action["request"]
                if e.get("exec_token") == request["exec_token"] and e.get("tgid") == request["tgid"] and e.get("process_start_ns") == request["start_ns"] and (e.get("device"), e.get("inode")) == (action.get("device"), action.get("inode")):
                    e["policy_timing"] = classify_operation(e, action)
        evidence = html.escape(json.dumps(facts, ensure_ascii=False, indent=2))
        quality = html.escape(json.dumps(alert.get("evidence_quality", {"status": "legacy_unknown"}), ensure_ascii=False, indent=2))
        actions = html.escape(json.dumps(action_rows, ensure_ascii=False, indent=2))
        sections.append(f"<article><h2>{esc(alert['rule_id'])} · {esc(alert['severity'])}</h2><p>{esc(alert['explanation'])}</p>"
                        f"<p>操作：{esc(alert['result_state'])}；处置：{esc(alert['action_state'])}；质量：{esc(alert['quality'])}</p>"
                        f"<h3>事实与来源</h3><ol>{nodes}</ol><details><summary>原始证据与时间线</summary><pre>{evidence}</pre></details>"
                        f"<h3>证据质量</h3><pre>{quality}</pre><h3>动作时间线</h3><pre>{actions}</pre>"
                        "<h3>成本</h3><p>请关联同轮性能文件；没有测量的成本保持未知。</p></article>")
    body = "\n".join(sections) or "<p>此数据库中没有告警；这不等于没有风险。</p>"
    Path(destination).write_text("<!doctype html><html lang='zh-CN'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
                                "<title>eBPF 告警证据报告</title><style>body{max-width:1100px;margin:40px auto;padding:0 20px;font:16px/1.65 system-ui;background:#f3f5f8;color:#16243a}article{background:white;border:1px solid #d9e0e9;border-radius:12px;padding:20px;margin:18px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}code{font-size:12px;overflow-wrap:anywhere}h1{color:#174b78}</style>"
                                "<h1>eBPF 告警证据报告</h1><p>本报告展示观测证据和规则判断；风险提示不等同于攻击成功。</p>" + body + "</html>", encoding="utf-8")


def classify_operation(event, action):
    start = event.get("operation_start_ns")
    if not start:
        return "unknown_operation_start"
    if event["monotonic_ns"] <= action["update_before_ns"]:
        return "before_application"
    if start >= action["expires_ns"]:
        return "after_expiry"
    if event["monotonic_ns"] >= action["expires_ns"]:
        return "expiry_boundary_uncertain"
    if start >= action["update_after_ns"]:
        return "after_application"
    return "application_boundary_uncertain"
