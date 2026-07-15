#!/usr/bin/env python3
"""NetFRAME daily rollup. Summarizes the last 24h of history.jsonl and asks the
local LLM for a daily health/events/trends/recommendations report. Separate from
the 15-min now-report (does not touch report.md). Reliability-first: defaults to
the fast 7B model so it never contends with the 15-min run; override
NETFRAME_LLM_MODEL=qwen2.5:72b for a deeper pass once contention is managed.

Read-only. Writes report-daily.md + reports/daily/<date>.md. Reverts by removing
this file and its timer."""
import datetime as dt
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netframe_policy  # noqa: E402 - path first; the gate is mandatory

BASE = "/opt/netframe-monitor"
HISTORY_FILE = f"{BASE}/history.jsonl"
CONTEXT_DIR = f"{BASE}/context"
CONTEXT_CAP = 16000
OUT = f"{BASE}/report-daily.md"
ARCHIVE_DIR = f"{BASE}/reports/daily"
OLLAMA_URL = os.environ.get("NETFRAME_OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.environ.get("NETFRAME_LLM_MODEL", "qwen2.5:7b")
LLM_TIMEOUT = int(os.environ.get("NETFRAME_LLM_TIMEOUT", "600"))

SYSTEM_PROMPT = (
    "You are the health analyst for the NetFRAME home-lab cluster, running locally on "
    "'Jarvis'. You are given a summary of the last 24 HOURS of 15-minute health runs (7 "
    "nodes: jarvis, randy [storage], quarkylab [GPU/ML], pve2-pve5). Write a CONCISE daily "
    "rollup in Markdown, under ~450 words, using EXACTLY these headers verbatim:\n"
    "## Day summary\n## Notable events\n## 24h trends\n## Fix before it breaks\n## Security\n\n"
    "- Day summary: one line on the day's posture (how many runs were nominal vs watch vs "
    "action, and the headline).\n"
    "- Notable events: verdict flips and NEW/recurring errors with COUNTS and the node; if a "
    "problem recurred N times, say so. If quiet, say 'Quiet day.'\n"
    "- 24h trends: metrics moving across the day (temps, disk %, pending/reallocated sectors), "
    "cite node + start->end numbers. Omit if none.\n"
    "- Fix before it breaks: prioritized, proactive. For the single most important item, give "
    "a one-line Situation/Evidence/Confidence/Action. Otherwise short bullets.\n"
    "- Security: posture notes vs the standing tracker; do not re-flag Resolved/Risk-Accepted.\n\n"
    "Use the STANDING OPERATIONAL CONTEXT below (architecture, reliability/SPOFs, known issues "
    "+ recent changes): do NOT raise known SPOFs or accepted risks as novel; attribute symptoms "
    "to recent changes when plausible; never recommend fsck on ZFS. Explain WHY, not just WHAT."
)


def load_context():
    if not os.path.isdir(CONTEXT_DIR):
        return ""
    chunks = []
    for fn in sorted(os.listdir(CONTEXT_DIR)):
        if fn.endswith(".md"):
            with open(os.path.join(CONTEXT_DIR, fn)) as fh:
                chunks.append(f"----- {fn} -----\n{fh.read()}")
    return "\n\n".join(chunks)[:CONTEXT_CAP]


def load_last_24h():
    if not os.path.exists(HISTORY_FILE):
        return []
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
    rows = []
    with open(HISTORY_FILE) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                ts = dt.datetime.fromisoformat(r["ts"])
                if ts >= cutoff:
                    rows.append(r)
            except (ValueError, KeyError):
                continue
    return rows


def summarize(rows):
    """Compact, model-friendly summary of the 24h window."""
    if not rows:
        return {"runs": 0}
    verdict_counts = {}
    flips = []
    prev = None
    check_fail = {}
    for r in rows:
        w = r.get("worst", "?")
        verdict_counts[w] = verdict_counts.get(w, 0) + 1
        if prev is not None and prev != w:
            flips.append({"ts": r["ts"], "from": prev, "to": w})
        prev = w
        for node, v in (r.get("verdicts") or {}).items():
            if v not in ("OK", "NOMINAL", None):
                check_fail[node] = check_fail.get(node, 0) + 1
    # metric deltas: first vs last record's metrics (flat numeric only)
    first_m, last_m = rows[0].get("metrics") or {}, rows[-1].get("metrics") or {}
    deltas = {}
    for k, v in last_m.items():
        try:
            fv = float(first_m.get(k))
            lv = float(v)
            if abs(lv - fv) > 0:
                deltas[k] = {"start": fv, "end": lv, "delta": round(lv - fv, 2)}
        except (TypeError, ValueError):
            continue
    return {
        "runs": len(rows),
        "window": {"start": rows[0]["ts"], "end": rows[-1]["ts"]},
        "verdict_counts": verdict_counts,
        "verdict_flips": flips[:20],
        "non_ok_by_node": dict(sorted(check_fail.items(), key=lambda x: -x[1])),
        "metric_deltas_24h": deltas,
    }


def call_llm(summary, standing):
    user = "24-hour rollup summary as JSON. Write the daily report.\n\n" + json.dumps(summary, indent=2)
    if standing:
        user += "\n\n=== STANDING OPERATIONAL CONTEXT ===\n" + standing
    payload = {
        "model": MODEL, "stream": False, "options": {"temperature": 0.2},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ],
    }
    req = urllib.request.Request(OLLAMA_URL, data=json.dumps(payload).encode(),
                                headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
        return json.loads(resp.read().decode())["message"]["content"].strip()


def main():
    rows = load_last_24h()
    summary = summarize(rows)
    now = dt.datetime.now(dt.timezone.utc)
    if summary["runs"] == 0:
        body = "## Day summary\nNo history in the last 24h.\n"
    else:
        try:
            body = call_llm(summary, load_context())
        except Exception as e:  # noqa: BLE001 - report degraded, never crash the timer
            body = (f"## Day summary\nLLM unavailable ({e}); raw 24h summary follows.\n\n"
                    f"```json\n{json.dumps(summary, indent=2)}\n```")
    # Same deterministic gate as every other LLM->operator path. No report type gets a
    # weaker boundary than another (NF-AIOPS-004 safety phase).
    body, _ = netframe_policy.enforce(body, source="daily")
    header = (f"# NetFRAME Daily Rollup\n\n_Generated {now.isoformat()} by {MODEL} on Jarvis · "
              f"{summary.get('runs', 0)} runs in the last 24h_\n\n---\n\n")
    report = header + body + "\n"
    with open(OUT, "w") as fh:
        fh.write(report)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    with open(f"{ARCHIVE_DIR}/{now:%Y-%m-%d}.md", "w") as fh:
        fh.write(report)
    print(f"daily rollup written by {MODEL}: {summary.get('runs', 0)} runs -> {OUT}")


if __name__ == "__main__":
    main()
