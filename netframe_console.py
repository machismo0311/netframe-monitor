#!/usr/bin/env python3
"""NetFRAME Operations Console server.

A small, read-only HTTP API + static console page. It exposes exactly three routes and
never serves a request-derived file path (no traversal). It reads Jarvis's memory and
proxies questions to the chat brain; it has NO endpoint that executes or approves
anything. Bind is guarded by iptables (localhost + NPM only) and fronted by NPM auth,
mirroring the health page.

Routes:
  GET  /            -> the console UI (a single fixed file)
  GET  /api/overview-> health/risk/incident/change summary
  GET  /api/panels  -> sidebar panel data (map, memory, incidents, recommendations, actions)
  POST /api/chat    -> {question, mode, deep} -> structured answer (read-only)
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
CONSOLE_HTML = f"{BASE}/web/console.html"
PORT = int(os.environ.get("NETFRAME_CONSOLE_PORT", "8809"))


def _read_json(path):
    try:
        return json.load(open(path))
    except (ValueError, OSError):
        return {}


def _read_jsonl(path, limit=None):
    if not os.path.exists(path):
        return []
    rows = []
    for line in open(path):
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows[-limit:] if limit else rows


def overview():
    state = _read_json(f"{BASE}/last_run.json")
    worst = state.get("worst", "?")
    nodes = state.get("nodes", {})
    node_ok = sum(1 for h, ck in nodes.items()
                  if all(c.get("verdict") in ("OK", None) for c in ck.values()))
    svc_total = sum(len(ck) for ck in nodes.values())
    svc_bad = sum(1 for ck in nodes.values() for c in ck.values()
                  if c.get("verdict") not in ("OK", None))
    pending = len(_read_jsonl(f"{BASE}/context/pending-remediation.jsonl"))
    # simple risk score: weighted non-OK + open predictive risk
    risk = min(100, svc_bad * 10 + (25 if "HIGH" in _read_text("report-predict.md") else 0))
    return {"verdict": worst, "risk": risk, "nodes_ok": node_ok, "nodes_total": len(nodes),
            "svc_bad": svc_bad, "svc_total": svc_total, "pending": pending,
            "collected": state.get("started", "")[:19]}


def _read_text(name):
    p = f"{BASE}/{name}"
    return open(p).read() if os.path.exists(p) else ""


def _node_verdicts():
    state = _read_json(f"{BASE}/last_run.json")
    out = {}
    for h, ck in state.get("nodes", {}).items():
        vs = [c.get("verdict") for c in ck.values()]
        out[h] = "crit" if any(v in ("AUTH-FAIL", "TIMEOUT") for v in vs) else (
            "warn" if any(v not in ("OK", None) for v in vs) else "ok")
    return out


def panels():
    # infra map from topology + live node verdicts
    topo = _read_json(f"{BASE}/knowledge/topology.json")
    verds = _node_verdicts()
    nmap = []
    for eid, e in topo.get("entities", {}).items():
        if e.get("type") == "node":
            deps = [d["dependent"] for d in topo.get("dependencies", []) if d["on"] == eid][:4]
            nmap.append({"name": eid, "role": e.get("role", "")[:40],
                         "state": verds.get(eid, "ok"), "deps": deps})
    # memory: EVT entries
    events = []
    for m in re.finditer(r"(EVT-\d+)[:\s]+([^\n]{0,70})", _read_text("context/30-known-events.md")):
        events.append({"id": m.group(1), "title": m.group(2).strip(" -*#")})
    # recommendations: P-tags from the chief report, tolerant of **P0**, ### P0, - P0:
    recs = []
    skip = {"immediate action", "schedule maintenance", "optimization", "future improvement",
            "action", "none"}
    for m in re.finditer(r"[#>*\s-]*\*{0,2}(P[0-3])\*{0,2}\s*[:\-]?\s*([^\n]{3,90})",
                         _read_text("report-chief.md")):
        txt = re.sub(r"^(immediate action|schedule maintenance|optimization|future improvement)"
                     r"\b[:\s-]*", "", m.group(2).strip(" -*:"), flags=re.I).strip(" -*:")
        if txt and txt.lower() not in skip and len(txt) > 4:
            recs.append({"prio": m.group(1), "text": txt[:80]})
    # actions: audit ledger tail
    actions = [{"event": a.get("event"), "action": a.get("action"), "actor": a.get("actor"),
                "ok": a.get("ok")} for a in _read_jsonl(f"{BASE}/context/incident-history.jsonl", 8)]
    return {"map": nmap, "events": events[:8], "recommendations": recs[:8],
            "actions": list(reversed(actions))}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            if os.path.exists(CONSOLE_HTML):
                self._send(200, open(CONSOLE_HTML, "rb").read(), "text/html; charset=utf-8")
            else:
                self._send(404, "console.html not deployed", "text/plain")
        elif path == "/api/overview":
            self._send(200, json.dumps(overview()))
        elif path == "/api/panels":
            self._send(200, json.dumps(panels()))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path.split("?")[0] != "/api/chat":
            self._send(404, json.dumps({"error": "not found"}))
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n).decode() or "{}")
        except (ValueError, TypeError):
            self._send(400, json.dumps({"error": "bad request"}))
            return
        q = (req.get("question") or "").strip()[:2000]
        mode = req.get("mode", "operator")
        deep = bool(req.get("deep"))
        if not q:
            self._send(400, json.dumps({"error": "empty question"}))
            return
        import netframe_chat
        result = netframe_chat.answer(q, mode, deep)
        self._send(200, json.dumps(result))


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"NetFRAME console on :{PORT} (read-only; iptables + NPM guard the bind)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
