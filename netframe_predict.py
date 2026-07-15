#!/usr/bin/env python3
"""NetFRAME predictive layer: 'what should I fix before it breaks'.

Read-only. Computes DETERMINISTIC trends from history.jsonl (no LLM does the math,
so predictions are reliable, not hallucinated):
  - Drive-failure risk: worst_pending / worst_realloc current value + slope/day.
    Rising reallocated/pending sectors are the classic pre-failure signal.
  - Capacity forecast: df/zpool %used linear-extrapolated to days-until-90%.
  - Thermal drift: max_temp_c slope/day.
An optional LLM pass narrates/prioritizes the computed facts (never computes them);
it degrades to the deterministic tables if the model is unavailable.

Writes report-predict.md + reports/predict/<date>.md. Reverts by removing the file
and its timer. Intended cadence: weekly (via netframe-predict.timer)."""
import datetime as dt
import json
import os
import urllib.request

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
HISTORY = f"{BASE}/history.jsonl"
CONTEXT_DIR = f"{BASE}/context"
OUT = f"{BASE}/report-predict.md"
ARCHIVE = f"{BASE}/reports/predict"
OLLAMA_URL = os.environ.get("NETFRAME_OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.environ.get("NETFRAME_LLM_MODEL", "qwen2.5:7b")
LLM_TIMEOUT = int(os.environ.get("NETFRAME_LLM_TIMEOUT", "600"))
DAYS = int(os.environ.get("NETFRAME_PREDICT_DAYS", "14"))
CAP_THRESHOLD = 90.0


def load_series():
    """Return ({metric_key: [(t_days_from_start, value), ...]}, runs, coverage_days)
    over the last DAYS. coverage_days is how much of that window the retained
    history actually spans, so the report can state a shortfall instead of
    silently trending over less data than it claims."""
    if not os.path.exists(HISTORY):
        return {}, 0, 0.0
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=DAYS)
    rows = []
    with open(HISTORY) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                t = dt.datetime.fromisoformat(d["ts"])
                if t >= cutoff:
                    rows.append((t, d.get("metrics") or {}))
            except (ValueError, KeyError):
                continue
    if not rows:
        return {}, 0, 0.0
    coverage = round((now - rows[0][0]).total_seconds() / 86400.0, 1)
    t0 = rows[0][0]
    series = {}
    for t, metrics in rows:
        td = (t - t0).total_seconds() / 86400.0
        for k, v in metrics.items():
            try:
                series.setdefault(k, []).append((td, float(v)))
            except (TypeError, ValueError):
                continue
    return series, len(rows), coverage


def linreg(points):
    """Least-squares slope (per day) and last value. Needs >=3 points."""
    n = len(points)
    if n < 3:
        return 0.0, (points[-1][1] if points else 0.0)
    sx = sum(p[0] for p in points)
    sy = sum(p[1] for p in points)
    sxx = sum(p[0] * p[0] for p in points)
    sxy = sum(p[0] * p[1] for p in points)
    denom = n * sxx - sx * sx
    slope = (n * sxy - sx * sy) / denom if denom else 0.0
    return slope, points[-1][1]


def analyze(series):
    # Only monotonic metrics are linear-trended: pending/reallocated sectors (step up
    # toward failure) and %used (climbs toward full). Temperatures oscillate daily and
    # are NOT linear-fit here (that produced spurious slopes); the 15-min/daily reports
    # handle thermal trends instead.
    drives, capacity = [], []
    for k, pts in series.items():
        slope, cur = linreg(pts)
        if k.endswith(".smart.worst_pending") or k.endswith(".smart.worst_realloc"):
            node = k.split(".")[0]
            kind = "pending" if "pending" in k else "reallocated"
            if cur > 0 or slope > 0.001:
                risk = "HIGH" if slope > 0.05 else ("WATCH" if (cur > 0 or slope > 0) else "OK")
                drives.append({"node": node, "kind": kind, "current": round(cur, 1),
                               "slope_per_day": round(slope, 3), "risk": risk})
        elif k.endswith(".df.max_use_pct") or k.endswith(".cap_pct"):
            if slope > 0.001 and cur < CAP_THRESHOLD:
                days = (CAP_THRESHOLD - cur) / slope
                if days < 90:
                    capacity.append({"metric": k, "current": round(cur, 1),
                                     "slope_per_day": round(slope, 3),
                                     "days_to_90pct": round(days, 1)})
    drives.sort(key=lambda d: (-{"HIGH": 2, "WATCH": 1}.get(d["risk"], 0), -d["slope_per_day"]))
    capacity.sort(key=lambda c: c["days_to_90pct"])
    return {"drives": drives, "capacity": capacity}


def det_tables(pred, runs, coverage):
    L = [f"_Deterministic trends over the last {DAYS} days ({runs} runs)._\n"]
    if coverage and coverage + 0.5 < DAYS:
        L.append(f"**Window shortfall:** retained history spans only {coverage}d of the "
                 f"requested {DAYS}d; slopes reflect the shorter span and are less certain.\n")
    L.append("## Drive-failure risk (pending / reallocated sectors)")
    if pred["drives"]:
        L.append("| Node | Metric | Current | Slope/day | Risk |")
        L.append("|---|---|---|---|---|")
        for d in pred["drives"]:
            L.append(f"| {d['node']} | {d['kind']} | {d['current']} | {d['slope_per_day']} | {d['risk']} |")
    else:
        L.append("No drive showing pending/reallocated sectors or a rising trend. (Age remains a "
                 "separate concern for the raidz1 pools; see the reliability context.)")
    L.append("\n## Capacity forecast (days to 90%)")
    if pred["capacity"]:
        L.append("| Metric | Current % | Slope/day | Days to 90% |")
        L.append("|---|---|---|---|")
        for c in pred["capacity"]:
            L.append(f"| {c['metric']} | {c['current']} | {c['slope_per_day']} | {c['days_to_90pct']} |")
    else:
        L.append("No filesystem/pool trending toward 90% within 90 days.")
    return "\n".join(L)


def load_context():
    if not os.path.isdir(CONTEXT_DIR):
        return ""
    ch = []
    for fn in sorted(os.listdir(CONTEXT_DIR)):
        if fn.endswith(".md"):
            with open(os.path.join(CONTEXT_DIR, fn)) as fh:
                ch.append(f"----- {fn} -----\n{fh.read()}")
    return "\n\n".join(ch)[:16000]


def narrate(pred):
    """One prioritized paragraph over the DETERMINISTIC facts. Never computes."""
    sys_p = (
        "You are the reliability analyst for the NetFRAME cluster. You are given DETERMINISTIC "
        "predictive trends (already computed; do NOT recompute or invent numbers). Write a short "
        "'Fix before it breaks' section (<180 words): rank the items by urgency, explain WHY each "
        "matters, and give a concrete action. Use the standing context (known SPOFs, raidz1 aged "
        "disks, known events); do not raise accepted risks as novel; never recommend fsck on ZFS. "
        "If everything is quiet, say the fleet is trending healthy and name the one thing to watch."
    )
    user = "Deterministic predictions (JSON):\n" + json.dumps(pred, indent=2)
    ctx = load_context()
    if ctx:
        user += "\n\n=== STANDING OPERATIONAL CONTEXT ===\n" + ctx
    payload = {"model": MODEL, "stream": False, "options": {"temperature": 0.2},
               "messages": [{"role": "system", "content": sys_p},
                            {"role": "user", "content": user}]}
    req = urllib.request.Request(OLLAMA_URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
        return json.loads(resp.read().decode())["message"]["content"].strip()


def main():
    series, runs, coverage = load_series()
    pred = analyze(series)
    now = dt.datetime.now(dt.timezone.utc)
    tables = det_tables(pred, runs, coverage)
    try:
        summary = narrate(pred)
    except Exception as e:  # noqa: BLE001 - deterministic tables still ship
        summary = f"_(LLM narration unavailable: {e}; deterministic tables below.)_"
    report = (f"# NetFRAME Predictive Report (fix before it breaks)\n\n"
              f"_Generated {now.isoformat()} on Jarvis · {runs} runs / {DAYS}d window · "
              f"narration by {MODEL}_\n\n---\n\n## Fix before it breaks\n{summary}\n\n---\n\n{tables}\n")
    with open(OUT, "w") as fh:
        fh.write(report)
    os.makedirs(ARCHIVE, exist_ok=True)
    with open(f"{ARCHIVE}/{now:%Y-%m-%d}.md", "w") as fh:
        fh.write(report)
    print(f"predictive report written: {len(pred['drives'])} drive-risk, "
          f"{len(pred['capacity'])} capacity -> {OUT}")


if __name__ == "__main__":
    main()
