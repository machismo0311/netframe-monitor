#!/usr/bin/env python3
"""NetFRAME monthly infrastructure-maturity report.

Read-only. Reasons over the last 30 days of history + the full standing context
(architecture, SPOFs, known-events ledger, recent changes) to assess how the
estate is maturing: reliability, observability, automation, security posture,
documentation. Uses the 72B model for depth (the deep-pass tier that runs on the
otherwise-idle GPUs); infrequent, so contention with the 15-min 7B run is minimal.

Writes report-monthly.md + reports/monthly/<date>.md. Reverts by removing the file
and its timer. Cadence: monthly (netframe-monthly.timer)."""
import datetime as dt
import json
import os
import urllib.request

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
HISTORY = f"{BASE}/history.jsonl"
CONTEXT_DIR = f"{BASE}/context"
PREDICT = f"{BASE}/report-predict.md"
OUT = f"{BASE}/report-monthly.md"
ARCHIVE = f"{BASE}/reports/monthly"
OLLAMA_URL = os.environ.get("NETFRAME_OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.environ.get("NETFRAME_LLM_MODEL", "qwen2.5:72b")
LLM_TIMEOUT = int(os.environ.get("NETFRAME_LLM_TIMEOUT", "900"))
DAYS = 30

SYSTEM_PROMPT = (
    "You are the principal SRE for the NetFRAME home-lab cluster. Write a MONTHLY "
    "infrastructure-maturity report (Markdown, ~500 words) using EXACTLY these headers:\n"
    "## Posture this month\n## Maturity by domain\n## What improved\n## Still open (ranked)\n"
    "## Watch next month\n\n"
    "- Posture this month: the month's overall reliability posture from the run summary "
    "(nominal vs watch/action share, any recurring incidents).\n"
    "- Maturity by domain: one line each for Reliability, Observability, Automation, Security, "
    "Documentation. Rate each Strong / Adequate / Developing and say why, grounded in the "
    "standing context (do not invent capabilities).\n"
    "- What improved: concrete changes landed recently (from the recent-changes context).\n"
    "- Still open (ranked): the tracked open items that most raise risk, most-important first. "
    "Use the known SPOFs and open-items context; do not present accepted risks as new.\n"
    "- Watch next month: the one or two things most likely to need attention, with why.\n\n"
    "Be specific and honest; this is a self-assessment, not marketing. Do not raise known "
    "SPOFs/accepted risks as novel; never recommend fsck on ZFS; apply lessons from the "
    "known-events ledger. Prefer explaining significance over listing metrics."
)


def load_context():
    if not os.path.isdir(CONTEXT_DIR):
        return ""
    ch = []
    for fn in sorted(os.listdir(CONTEXT_DIR)):
        if fn.endswith(".md"):
            with open(os.path.join(CONTEXT_DIR, fn)) as fh:
                ch.append(f"----- {fn} -----\n{fh.read()}")
    return "\n\n".join(ch)[:16000]


def summarize_30d():
    if not os.path.exists(HISTORY):
        return {"runs": 0}
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=DAYS)
    rows = []
    with open(HISTORY) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                if dt.datetime.fromisoformat(d["ts"]) >= cutoff:
                    rows.append(d)
            except (ValueError, KeyError):
                continue
    if not rows:
        return {"runs": 0}
    verdicts, flips, prev, nonok = {}, 0, None, {}
    for r in rows:
        w = r.get("worst", "?")
        verdicts[w] = verdicts.get(w, 0) + 1
        if prev is not None and prev != w:
            flips += 1
        prev = w
        for node, v in (r.get("verdicts") or {}).items():
            if v not in ("OK", "NOMINAL", None):
                nonok[node] = nonok.get(node, 0) + 1
    return {"runs": len(rows), "window_days": DAYS, "verdict_counts": verdicts,
            "verdict_flips": flips,
            "non_ok_by_node": dict(sorted(nonok.items(), key=lambda x: -x[1])[:8])}


def narrate(summary):
    user = "30-day run summary (JSON):\n" + json.dumps(summary, indent=2)
    pred = ""
    if os.path.exists(PREDICT):
        with open(PREDICT) as fh:
            pred = fh.read()[:2000]
    if pred:
        user += "\n\n=== LATEST PREDICTIVE REPORT (drive/capacity forecast) ===\n" + pred
    ctx = load_context()
    if ctx:
        user += "\n\n=== STANDING OPERATIONAL CONTEXT ===\n" + ctx
    payload = {"model": MODEL, "stream": False, "options": {"temperature": 0.2},
               "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user}]}
    req = urllib.request.Request(OLLAMA_URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
        return json.loads(resp.read().decode())["message"]["content"].strip()


def main():
    summary = summarize_30d()
    now = dt.datetime.now(dt.timezone.utc)
    if summary["runs"] == 0:
        body = "## Posture this month\nNo history in the last 30 days.\n"
    else:
        try:
            body = narrate(summary)
        except Exception as e:  # noqa: BLE001 - report degraded, never crash the timer
            body = (f"## Posture this month\nLLM unavailable ({e}); raw 30d summary:\n\n"
                    f"```json\n{json.dumps(summary, indent=2)}\n```")
    report = (f"# NetFRAME Monthly Maturity Report\n\n_Generated {now.isoformat()} by {MODEL} "
              f"on Jarvis · {summary.get('runs', 0)} runs / {DAYS}d_\n\n---\n\n{body}\n")
    with open(OUT, "w") as fh:
        fh.write(report)
    os.makedirs(ARCHIVE, exist_ok=True)
    with open(f"{ARCHIVE}/{now:%Y-%m}.md", "w") as fh:
        fh.write(report)
    print(f"monthly report written by {MODEL}: {summary.get('runs', 0)} runs -> {OUT}")


if __name__ == "__main__":
    main()
