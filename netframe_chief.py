#!/usr/bin/env python3
"""NetFRAME Weekly Chief Engineer Report (Phase 7).

Read-only synthesis. Reasons over everything Jarvis already produced this week (the
latest health interpretation, predictive forecast, config-drift report, GitHub review,
the audit ledger, and the known-events + blast-radius context) and writes one
prioritized weekly report for the owner, under the constitution's principles. The 72B
deep-pass tier; weekly, so GPU contention is minimal.

Recommendations are ranked P0 (immediate action) / P1 (schedule maintenance) /
P2 (optimization) / P3 (future improvement).

Writes report-chief.md + reports/chief/<date>.md. Cadence: weekly (netframe-chief.timer).
"""
import datetime as dt
import json
import os
import urllib.request

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
CONSTITUTION_DIR = f"{BASE}/constitution"
LEDGER = f"{BASE}/context/incident-history.jsonl"
OUT = f"{BASE}/report-chief.md"
ARCHIVE = f"{BASE}/reports/chief"
OLLAMA_URL = os.environ.get("NETFRAME_OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.environ.get("NETFRAME_LLM_MODEL", "qwen2.5:72b")
LLM_TIMEOUT = int(os.environ.get("NETFRAME_LLM_TIMEOUT", "900"))

# report file -> the section of the weekly report it primarily informs
SOURCES = {
    "report.md": "current health interpretation",
    "report-predict.md": "predictive forecast (drive/capacity)",
    "report-confdrift.md": "configuration drift vs baseline",
    "report-github.md": "GitHub engineering review",
}
CAP = 3500  # chars kept per source, so the whole prompt stays bounded

SYSTEM_PROMPT = (
    "You are the Chief Engineer for the NetFRAME infrastructure, writing the WEEKLY report "
    "for the owner. You are given this week's machine-generated reports and the audit "
    "ledger. Synthesize them; do not just concatenate. Ground every statement in the "
    "provided material and cite the specific signal. Use EXACTLY these headers:\n"
    "## Executive summary\n## Infrastructure health\n## Recent changes\n## Detected risks\n"
    "## Trends\n## Capacity\n## Security observations\n## Recommendations\n\n"
    "Under Recommendations, group items by priority and label each line with its tag:\n"
    "- **P0** immediate action (something is broken or about to break)\n"
    "- **P1** schedule maintenance (needs a window soon)\n"
    "- **P2** optimization (worth doing, not urgent)\n"
    "- **P3** future improvement\n"
    "If a priority band has nothing, write 'none'. Be concise and concrete, name nodes and "
    "numbers, and never recommend an action the authority limits forbid. No em dashes.")


def read_cap(path, cap=CAP):
    if os.path.exists(f"{BASE}/{path}"):
        return open(f"{BASE}/{path}").read()[:cap]
    return ""


def load_constitution():
    if not os.path.isdir(CONSTITUTION_DIR):
        return ""
    ch = []
    for fn in sorted(os.listdir(CONSTITUTION_DIR)):
        if fn.endswith(".md"):
            ch.append(open(os.path.join(CONSTITUTION_DIR, fn)).read())
    return "\n\n".join(ch)


def recent_ledger(days=7):
    if not os.path.exists(LEDGER):
        return []
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    out = []
    for line in open(LEDGER):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            ts = dt.datetime.fromisoformat(r["ts"])
            if ts >= cutoff:
                out.append({k: r.get(k) for k in ("ts", "actor", "event", "action", "ok")})
        except (ValueError, KeyError):
            continue
    return out


def build_user():
    parts = ["This week's reports and ledger:\n"]
    for path, label in SOURCES.items():
        content = read_cap(path)
        if content:
            parts.append(f"=== {label} ({path}) ===\n{content}\n")
    ledger = recent_ledger()
    parts.append("=== audit ledger, last 7 days (actions Jarvis proposed/took) ===\n"
                 + (json.dumps(ledger, indent=2) if ledger else "no recorded actions this week"))
    return "\n".join(parts)


def narrate():
    messages = []
    constitution = load_constitution()
    if constitution:
        messages.append({"role": "system", "content":
                         "Your permanent operating principles (highest authority):\n\n"
                         + constitution})
    messages.append({"role": "system", "content": SYSTEM_PROMPT})
    messages.append({"role": "user", "content": build_user()})
    payload = {"model": MODEL, "stream": False, "options": {"temperature": 0.2},
               "messages": messages}
    req = urllib.request.Request(OLLAMA_URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
        return json.loads(resp.read().decode())["message"]["content"].strip()


def main():
    now = dt.datetime.now(dt.timezone.utc)
    try:
        body = narrate()
    except Exception as e:  # noqa: BLE001 - never crash the timer
        body = f"## Executive summary\nLLM synthesis unavailable ({e}); source reports stand alone."
    report = (f"# NetFRAME Weekly Chief Engineer Report\n\n_Generated {now.isoformat()} by "
              f"{MODEL} on Jarvis · read-only, recommend-only_\n\n---\n\n{body}\n")
    with open(OUT, "w") as fh:
        fh.write(report)
    os.makedirs(ARCHIVE, exist_ok=True)
    with open(f"{ARCHIVE}/{now.date().isoformat()}.md", "w") as fh:
        fh.write(report)
    print(f"weekly chief report written by {MODEL} -> {OUT}")


if __name__ == "__main__":
    main()
