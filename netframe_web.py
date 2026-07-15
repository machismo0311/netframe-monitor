#!/usr/bin/env python3
"""NetFRAME memory dashboard: one pane over everything Jarvis knows.

Read-only renderer. Assembles a single self-contained web/index.html with tabs, from
the artifacts already on disk (no new data, no external assets):
  Health          report.md            (15-min interpretation)
  Predict         report-predict.md    (drive/capacity forecast)
  Config drift    report-confdrift.md  (host config vs approved baseline)
  GitHub          report-github.md     (weekly engineering review)
  Monthly         report-monthly.md    (72B maturity report)
  Remediation     context/incident-history.jsonl + pending-remediation.jsonl
                  (open proposals + approved/rejected/executed actions = memory)
  Events          context/30-known-events.md   (recognized events + lessons)
  Inventory       context/00-architecture.md + 10-reliability-spofs.md

Runs at the end of netframe-run.sh (after the interpreter) so index.html is always
the dashboard. The interpreter writes its standalone page to web/health.html.
"""
import datetime as dt
import html
import json
import os
import re

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
CONTEXT = f"{BASE}/context"
WEB = f"{BASE}/web/index.html"
REFRESH = int(os.environ.get("NETFRAME_WEB_REFRESH", "900"))

# tab id, label, markdown source path (None => rendered specially)
TABS = [
    ("health", "Health", f"{BASE}/report.md"),
    ("predict", "Predict", f"{BASE}/report-predict.md"),
    ("drift", "Config drift", f"{BASE}/report-confdrift.md"),
    ("github", "GitHub", f"{BASE}/report-github.md"),
    ("monthly", "Monthly", f"{BASE}/report-monthly.md"),
    ("remediation", "Remediation", None),
    ("events", "Events", f"{CONTEXT}/30-known-events.md"),
    ("inventory", "Inventory", f"{CONTEXT}/00-architecture.md"),
]

_INLINE = [
    (re.compile(r"`([^`]+)`"), r"<code>\1</code>"),
    (re.compile(r"\*\*([^*]+)\*\*"), r"<strong>\1</strong>"),
]


def _inline(text):
    out = html.escape(text)
    for pat, repl in _INLINE:
        out = pat.sub(repl, out)
    return out


def md_to_html(md):
    """Compact markdown -> HTML: headings, tables, lists, hr, bold, code, paragraphs."""
    lines = md.splitlines()
    out, i, n = [], 0, len(lines)
    while i < n:
        line = lines[i].rstrip()
        if not line.strip():
            i += 1
            continue
        if line.startswith("### "):
            out.append(f"<h3>{_inline(line[4:])}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{_inline(line[2:])}</h1>")
        elif line.startswith("---") and set(line) <= {"-"}:
            out.append("<hr>")
        elif line.startswith("|") and i + 1 < n and re.match(r"^\|[\s:|-]+\|?\s*$", lines[i + 1]):
            head = [c.strip() for c in line.strip("|").split("|")]
            out.append("<div class='tw'><table><thead><tr>"
                       + "".join(f"<th>{_inline(c)}</th>" for c in head)
                       + "</tr></thead><tbody>")
            i += 2
            while i < n and lines[i].lstrip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
                i += 1
            out.append("</tbody></table></div>")
            continue
        elif line.lstrip().startswith(("- ", "* ")):
            out.append("<ul>")
            while i < n and lines[i].lstrip().startswith(("- ", "* ")):
                out.append(f"<li>{_inline(lines[i].lstrip()[2:])}</li>")
                i += 1
            out.append("</ul>")
            continue
        else:
            out.append(f"<p>{_inline(line)}</p>")
        i += 1
    return "\n".join(out) or "<p class='muted'>Not generated yet.</p>"


def read_md(path):
    if path and os.path.exists(path):
        return md_to_html(open(path).read())
    return "<p class='muted'>Not generated yet. This report runs on its own schedule.</p>"


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    for ln in open(path):
        ln = ln.strip()
        if ln:
            try:
                rows.append(json.loads(ln))
            except ValueError:
                continue
    return rows


def remediation_html():
    pending = read_jsonl(f"{CONTEXT}/pending-remediation.jsonl")
    hist = read_jsonl(f"{CONTEXT}/incident-history.jsonl")
    parts = ["<h2>Open proposals (awaiting your approval)</h2>"]
    if pending:
        parts.append("<div class='tw'><table><thead><tr><th>#</th><th>Action</th><th>Tier</th>"
                     "<th>Conf</th><th>Reason</th></tr></thead><tbody>")
        for p in pending:
            parts.append(f"<tr><td>{p.get('id')}</td><td><code>{html.escape(str(p.get('action')))}"
                         f"</code></td><td>{p.get('tier')}</td><td>{p.get('confidence')}%</td>"
                         f"<td>{html.escape(str(p.get('reason', '')))}</td></tr>")
        parts.append("</tbody></table></div>")
    else:
        parts.append("<p class='muted'>None. Jarvis proposes; it never acts without your "
                     "explicit approval.</p>")
    parts.append("<h2>Action ledger (approved, rejected, executed)</h2>")
    if hist:
        parts.append("<div class='tw'><table><thead><tr><th>When (UTC)</th><th>Event</th>"
                     "<th>Action</th><th>Result</th></tr></thead><tbody>")
        for h in reversed(hist[-100:]):
            ev = html.escape(str(h.get("event", "")))
            cls = {"executed": "ok", "rejected": "warn", "tier2-refused": "bad"}.get(
                h.get("event"), "")
            res = "ok" if h.get("ok") else ("fail" if "ok" in h else "")
            parts.append(f"<tr><td>{html.escape(str(h.get('ts', ''))[:19])}</td>"
                         f"<td><span class='badge {cls}'>{ev}</span></td>"
                         f"<td><code>{html.escape(str(h.get('action', '')))}</code></td>"
                         f"<td>{res}</td></tr>")
        parts.append("</tbody></table></div>")
    else:
        parts.append("<p class='muted'>No actions yet. Every proposal, approval, rejection, "
                     "and execution is recorded here as operational memory.</p>")
    return "\n".join(parts)


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="{refresh}">
<title>JARVIS · NetFRAME memory</title>
<style>
:root{{--bg:#f7f8fa;--fg:#1c2128;--card:#fff;--muted:#6a737d;--line:#e1e4e8;--accent:#2563eb}}
@media(prefers-color-scheme:dark){{:root{{--bg:#0d1117;--fg:#e6edf3;--card:#161b22;--muted:#8b949e;--line:#30363d;--accent:#58a6ff}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:960px;margin:0 auto;padding:1.5rem 1.25rem}}
.hero{{text-align:center;margin:.5rem 0 1rem}}
.hero h1{{font-size:1.8rem;font-weight:300;letter-spacing:.02em;margin:.2rem 0}}
.hero .sub{{font-size:.75rem;text-transform:uppercase;letter-spacing:.18em;color:var(--muted)}}
nav{{display:flex;flex-wrap:wrap;gap:.4rem;justify-content:center;margin:1rem 0}}
nav button{{background:var(--card);color:var(--fg);border:1px solid var(--line);
border-radius:999px;padding:.35rem .9rem;font:inherit;font-size:.85rem;cursor:pointer}}
nav button.active{{background:var(--accent);color:#fff;border-color:var(--accent)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1.25rem 1.5rem}}
.tab{{display:none}}.tab.active{{display:block}}
h1{{font-size:1.4rem;margin:.2rem 0 1rem}}h2{{font-size:1.05rem;margin:1.3rem 0 .4rem;
color:var(--accent);border-bottom:1px solid var(--line);padding-bottom:.3rem}}
h3{{font-size:.98rem;margin:1rem 0 .3rem}}
ul{{margin:.3rem 0 .3rem 1.1rem;padding:0}}li{{margin:.15rem 0}}
hr{{border:0;border-top:1px solid var(--line);margin:1rem 0}}
code{{background:rgba(127,127,127,.15);padding:.1em .35em;border-radius:5px;font-size:.9em}}
.muted{{color:var(--muted);font-size:.92rem}}
.tw{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;font-size:.9rem;margin:.4rem 0}}
th,td{{border:1px solid var(--line);padding:.35rem .55rem;text-align:left;vertical-align:top}}
th{{background:rgba(127,127,127,.08)}}
.badge{{display:inline-block;padding:.15em .6em;border-radius:999px;font-weight:600;font-size:.78rem}}
.ok{{background:#1a7f37;color:#fff}}.warn{{background:#bf8700;color:#fff}}.bad{{background:#cf222e;color:#fff}}
footer{{margin-top:1rem;text-align:center}}
</style></head><body><div class="wrap">
<div class="hero"><h1>Good {part}, sir</h1>
<div class="sub">J.A.R.V.I.S · NetFRAME operational memory</div></div>
<nav>{navbtns}</nav>
{panels}
<footer class="muted">Auto-refreshes every {refresh}s · read-only · generated locally on Jarvis · {stamp}</footer>
</div>
<script>
document.querySelectorAll('nav button').forEach(function(b){{
 b.addEventListener('click',function(){{
  document.querySelectorAll('nav button').forEach(function(x){{x.classList.remove('active')}});
  document.querySelectorAll('.tab').forEach(function(x){{x.classList.remove('active')}});
  b.classList.add('active');
  document.getElementById('tab-'+b.dataset.t).classList.add('active');
 }});
}});
</script></body></html>"""


def main():
    now = dt.datetime.now(dt.timezone.utc)
    hour = now.astimezone().hour
    part = "morning" if hour < 12 else "afternoon" if hour < 18 else "evening"
    navbtns, panels = [], []
    for idx, (tid, label, src) in enumerate(TABS):
        active = " active" if idx == 0 else ""
        navbtns.append(f'<button class="{active.strip()}" data-t="{tid}">{label}</button>')
        body = remediation_html() if tid == "remediation" else read_md(src)
        panels.append(f'<div id="tab-{tid}" class="tab{active} card">{body}</div>')
    doc = TEMPLATE.format(refresh=REFRESH, part=part, stamp=now.isoformat(),
                          navbtns="\n".join(navbtns), panels="\n".join(panels))
    os.makedirs(os.path.dirname(WEB), exist_ok=True)
    with open(WEB, "w") as fh:
        fh.write(doc)
    os.chmod(WEB, 0o644)
    print(f"dashboard written -> {WEB} ({len(TABS)} tabs)")


if __name__ == "__main__":
    main()
