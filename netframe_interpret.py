#!/usr/bin/env python3
"""NetFRAME monitor — LLM interpretation layer (runs on Jarvis).

Reads the collector's output (last_run.json + history.jsonl), computes what
changed since the previous run and trends across the recent window, then asks
Jarvis's local Ollama model to write a plain-English report with prioritized
recommendations and security-relevant observations.

Output: /opt/netframe-monitor/report.md (latest) + reports/report-<ts>.md archive.
Fully local/offline — talks only to http://localhost:11434. If the LLM is
unreachable it still writes a deterministic fallback report and exits 0, so it
never breaks the monitor timer.
"""

import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

BASE = "/opt/netframe-monitor"
STATE_FILE = f"{BASE}/last_run.json"
HISTORY_FILE = f"{BASE}/history.jsonl"
REPORT_FILE = f"{BASE}/report.md"
REPORT_DIR = f"{BASE}/reports"
REPORT_KEEP = 96  # ~24h of archives at 15-min cadence
CONTEXT_DIR = f"{BASE}/context"   # optional standing context (*.md), e.g. pentest tracker
CONTEXT_CAP = 6000                # max chars of context fed to the model
WEB_DIR = f"{BASE}/web"           # served over HTTP (never contains the key)
WEB_FILE = f"{WEB_DIR}/index.html"
WEB_REFRESH = 120                 # <meta refresh> seconds
# JARVIS greeting shown as the page hero (override with NETFRAME_GREETING).
GREETING = os.environ.get("NETFRAME_GREETING", "At your service, sir.")

OLLAMA_URL = os.environ.get("NETFRAME_OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.environ.get("NETFRAME_LLM_MODEL", "qwen2.5:7b")
WINDOW = 12          # recent history runs used for trend context (~3h)
LLM_TIMEOUT = 180

SYSTEM_PROMPT = (
    "You are the health analyst for the NetFRAME home-lab cluster, running locally "
    "on the node 'Jarvis'. You are given read-only telemetry collected every 15 "
    "minutes from 7 nodes (jarvis, randy [SuperMicro PBS/ZFS storage], quarkylab "
    "[R730 GPU/ML], pve2-pve5 [EliteDesk Proxmox nodes]). Write a CONCISE Markdown "
    "report for the operator (Kyle) under ~400 words.\n\n"
    "Use EXACTLY these five section headers, verbatim, with NO extra text after them:\n"
    "## Overall\n## What changed\n## Trends\n## Recommendations\n## Security\n\n"
    "Section contents:\n"
    "- Overall: one line — NOMINAL, WATCH, or ACTION NEEDED — plus a one-sentence why.\n"
    "- What changed: only real deltas vs the previous run (verdict flips, new errors, "
    "metric jumps). If nothing changed, write exactly 'No material change.'\n"
    "- Trends: anything moving across the window (disk % climbing, temps rising, "
    "pending/reallocated sectors increasing). Cite node + numbers. Omit if none.\n"
    "- Recommendations: prioritized, most important first, concrete and actionable. "
    "If all nominal, say so and recommend nothing.\n"
    "- Security: auth failures, unexpected service failures, or posture notes from the "
    "telemetry. If a STANDING SECURITY CONTEXT (pentest remediation tracker) is provided "
    "below, cross-reference it: call out telemetry that relates to an OPEN/Partial/Pending "
    "finding, and do not re-flag findings already marked Resolved or Risk-Accepted. If "
    "nothing is relevant, say 'Nothing security-relevant in this telemetry.'\n\n"
    "Rules: be specific; reference node names and numbers. Do NOT invent problems. The "
    "following are NORMAL and must NOT be reported as faults:\n"
    "  * Proxmox pmxcfs corosync messages at boot (quorum_initialize / cmap_initialize / "
    "cpg_initialize failed, 'failed to connect to corosync') — these are one-time startup "
    "ordering noise. Only flag them if they clearly recur long AFTER boot.\n"
    "  * A USB-bridge disk that needs '-d', or a SAS disk whose '-H' errors while its "
    "attribute health passes.\n"
    "  * ACPI/BIOS/SGX/blkmapd/openipmi kernel warnings at boot.\n"
    "Judge SMART by the parsed metrics (failed list, pending/reallocated counts), not by "
    "the presence of the word 'failed' in raw text."
)


def load_state():
    with open(STATE_FILE) as fh:
        return json.load(fh)


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    out = []
    with open(HISTORY_FILE) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def compute_changes(history):
    """Verdict flips and notable metric deltas: current vs previous run."""
    if len(history) < 2:
        return {"verdict_changes": {}, "metric_deltas": {}, "note": "no prior run to diff"}
    cur, prev = history[-1], history[-2]
    vc = {k: [prev.get("verdicts", {}).get(k), v]
          for k, v in cur.get("verdicts", {}).items()
          if prev.get("verdicts", {}).get(k) != v}
    md = {}
    pcur, pprev = cur.get("metrics", {}), prev.get("metrics", {})
    for k, v in pcur.items():
        pv = pprev.get(k)
        if isinstance(v, (int, float)) and isinstance(pv, (int, float)) and v != pv:
            # surface any sector change, or metric moves of >=3 (pct/deg)
            if "pending" in k or "realloc" in k or abs(v - pv) >= 3:
                md[k] = {"from": pv, "to": v}
    return {"verdict_changes": vc, "metric_deltas": md}


def compute_trends(history):
    """First vs last across the recent window for numeric metrics."""
    window = history[-WINDOW:]
    if len(window) < 3:
        return {}
    first, last = window[0].get("metrics", {}), window[-1].get("metrics", {})
    trends = {}
    for k, v in last.items():
        fv = first.get(k)
        if isinstance(v, (int, float)) and isinstance(fv, (int, float)) and v != fv:
            if "pending" in k or "realloc" in k or abs(v - fv) >= 3:
                trends[k] = {"window_start": fv, "now": v, "over_runs": len(window)}
    return trends


def build_context(state, changes, trends):
    """Compact JSON the model reasons over — verdicts, key metrics, notable raw."""
    nodes = {}
    notable = {}
    for host, checks in state.get("nodes", {}).items():
        nodes[host] = {}
        for name, c in checks.items():
            nodes[host][name] = {"verdict": c["verdict"], "metrics": c.get("metrics", {})}
            # include raw only where it carries signal the model should read
            if name == "journal_errors" and c.get("metrics", {}).get("error_lines"):
                notable[f"{host}.journal"] = c.get("raw_excerpt", "")[:800]
            if name == "smart" and c.get("metrics", {}).get("failed"):
                notable[f"{host}.smart_failed"] = c.get("raw_excerpt", "")[:800]
    return {
        "collected_at": state.get("started"),
        "overall_verdict": state.get("worst"),
        "nodes": nodes,
        "changes_since_last_run": changes,
        "trends_recent_window": trends,
        "notable_raw": notable,
    }


def load_context():
    """Concatenate optional standing-context .md files (e.g. pentest tracker)."""
    if not os.path.isdir(CONTEXT_DIR):
        return ""
    chunks = []
    for fn in sorted(os.listdir(CONTEXT_DIR)):
        if fn.endswith(".md"):
            try:
                with open(os.path.join(CONTEXT_DIR, fn)) as fh:
                    chunks.append(f"----- {fn} -----\n{fh.read()}")
            except OSError:
                pass
    return "\n\n".join(chunks)[:CONTEXT_CAP]


def call_llm(context, standing_context):
    user = "Here is the latest cluster telemetry as JSON. Write the report.\n\n" \
        + json.dumps(context, indent=2)
    if standing_context:
        user += ("\n\n=== STANDING SECURITY CONTEXT (pentest remediation tracker; "
                 "use for the Security section) ===\n" + standing_context)
    payload = {
        "model": MODEL,
        "stream": False,
        "options": {"temperature": 0.2},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ],
    }
    req = urllib.request.Request(
        OLLAMA_URL, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
        data = json.loads(resp.read().decode())
    return data["message"]["content"].strip()


def fallback_report(context, err):
    lines = [f"_LLM interpretation unavailable ({err}); showing deterministic summary._\n"]
    lines.append(f"**Overall:** {context['overall_verdict']}\n")
    for host, checks in context["nodes"].items():
        flat = " ".join(f"{n}:{c['verdict']}" for n, c in checks.items())
        lines.append(f"- **{host}** — {flat}")
    if context["changes_since_last_run"].get("verdict_changes"):
        lines.append(f"\n**Changes:** {context['changes_since_last_run']['verdict_changes']}")
    return "\n".join(lines)


def write_report(body, state):
    ts = datetime.now(timezone.utc)
    header = (f"# NetFRAME Cluster Health — Interpretation\n\n"
              f"_Generated {ts.isoformat()} by {MODEL} on Jarvis · "
              f"data collected {state.get('started')} · overall `{state.get('worst')}`_\n\n---\n\n")
    content = header + body + "\n"
    with open(REPORT_FILE, "w") as fh:
        fh.write(content)
    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = ts.strftime("%Y%m%dT%H%M%SZ")
    with open(f"{REPORT_DIR}/report-{stamp}.md", "w") as fh:
        fh.write(content)
    archives = sorted(f for f in os.listdir(REPORT_DIR) if f.startswith("report-"))
    for old in archives[:-REPORT_KEEP]:
        try:
            os.remove(f"{REPORT_DIR}/{old}")
        except OSError:
            pass


def _md_inline(text):
    import html
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text


def markdown_to_html(md):
    """Minimal converter for the report's subset: #/##, ---, - lists, **bold**, `code`."""
    out, in_ul = [], False
    for line in md.splitlines():
        if in_ul and not line.lstrip().startswith("- "):
            out.append("</ul>"); in_ul = False
        s = line.strip()
        if s == "---":
            out.append("<hr>")
        elif s.startswith("## "):
            out.append(f"<h2>{_md_inline(s[3:])}</h2>")
        elif s.startswith("# "):
            out.append(f"<h1>{_md_inline(s[2:])}</h1>")
        elif s.startswith("- "):
            if not in_ul:
                out.append("<ul>"); in_ul = True
            out.append(f"<li>{_md_inline(s[2:])}</li>")
        elif s.startswith("_") and s.endswith("_") and len(s) > 1:
            out.append(f'<p class="muted">{_md_inline(s.strip("_"))}</p>')
        elif s:
            out.append(f"<p>{_md_inline(s)}</p>")
    if in_ul:
        out.append("</ul>")
    return "\n".join(out)


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="{refresh}">
<title>JARVIS · {greeting}</title>
<style>
:root{{--bg:#f7f8fa;--fg:#1c2128;--card:#fff;--muted:#6a737d;--line:#e1e4e8;--accent:#2563eb}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--fg:#e6edf3;--card:#161b22;--muted:#8b949e;--line:#30363d;--accent:#58a6ff}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:820px;margin:0 auto;padding:2rem 1.25rem}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1.5rem 1.75rem}}
h1{{font-size:1.4rem;margin:.2rem 0 1rem}}h2{{font-size:1.05rem;margin:1.4rem 0 .4rem;
color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:.3rem}}
ul{{margin:.3rem 0 .3rem 1.1rem;padding:0}}li{{margin:.15rem 0}}
hr{{border:0;border-top:1px solid var(--line);margin:1rem 0}}
code{{background:rgba(127,127,127,.15);padding:.1em .35em;border-radius:5px;font-size:.9em}}
.muted{{color:var(--muted);font-size:.9rem}}
.badge{{display:inline-block;padding:.2em .7em;border-radius:999px;font-weight:600;font-size:.85rem}}
.ok{{background:#1a7f37;color:#fff}}.warn{{background:#bf8700;color:#fff}}.bad{{background:#cf222e;color:#fff}}
.hero{{text-align:center;margin:.5rem 0 1.5rem}}
.hero h1{{font-size:1.9rem;font-weight:300;letter-spacing:.02em;margin:.2rem 0}}
.hero .sub{{font-size:.8rem;text-transform:uppercase;letter-spacing:.18em;color:var(--muted)}}
footer{{margin-top:1rem;text-align:center}}
</style></head><body><div class="wrap">
<div class="hero"><h1>{greeting}</h1><div class="sub">J.A.R.V.I.S · NetFRAME cluster</div></div>
<div class="card">{badge}{body}</div>
<footer class="muted">Auto-refreshes every {refresh}s · generated locally on Jarvis by {model}</footer>
</div></body></html>"""


def write_html(body_md, state):
    worst = (state.get("worst") or "OK").upper()
    cls = {"OK": "ok", "WARN": "warn", "AUTH-FAIL": "bad", "TIMEOUT": "bad"}.get(worst, "warn")
    badge = f'<div style="margin-bottom:.5rem"><span class="badge {cls}">Overall: {worst}</span></div>'
    import html as _html
    html_doc = HTML_TEMPLATE.format(refresh=WEB_REFRESH, model=MODEL,
                                    greeting=_html.escape(GREETING),
                                    badge=badge, body=markdown_to_html(body_md))
    os.makedirs(WEB_DIR, exist_ok=True)
    with open(WEB_FILE, "w") as fh:
        fh.write(html_doc)
    os.chmod(WEB_FILE, 0o644)


def main():
    try:
        state = load_state()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read {STATE_FILE}: {exc}", file=sys.stderr)
        return 1
    history = load_history()
    changes = compute_changes(history)
    trends = compute_trends(history)
    context = build_context(state, changes, trends)
    standing_context = load_context()
    try:
        body = call_llm(context, standing_context)
        print(f"interpretation written by {MODEL}"
              + (" (with security context)" if standing_context else ""))
    except Exception as exc:  # noqa: BLE001 - never break the timer over the LLM
        body = fallback_report(context, exc)
        print(f"WARN: LLM call failed ({exc}); wrote fallback report", file=sys.stderr)
    write_report(body, state)
    # Render the exact report.md content (header + body) to the served web page.
    try:
        with open(REPORT_FILE) as fh:
            write_html(fh.read(), state)
        print(f"page -> {WEB_FILE}")
    except OSError as exc:
        print(f"WARN: could not write {WEB_FILE}: {exc}", file=sys.stderr)
    print(f"report -> {REPORT_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
