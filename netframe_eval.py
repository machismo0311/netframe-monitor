#!/usr/bin/env python3
"""NetFRAME AI evaluation harness (JAR-06). Runs the REAL interpreter against frozen
scenarios and checks behavioral assertions. Runs on Jarvis (needs the live model + the
standing context); NOT in GitHub CI, which has no Ollama. The deterministic unit tests in
tests/ cover the CI side.

Each eval/scenarios/*.json is a last_run.json-shaped state plus an `_eval` block:
  require_headers        every header must appear (well-formed report)
  expect_substrings      case-insensitive substrings that MUST appear
  prohibited_substrings  substrings that must NOT appear (e.g. fsck on ZFS, power-cycle)
  expect_injection_stamp the deterministic injection note must appear
  max_overall            SOFT: verdict calibration ceiling (varies run-to-run, tracked not gated)

Usage:  python3 netframe_eval.py [--scenario NAME]
Exit 0 = all pass, 1 = any fail. Run before deploying any interpreter/prompt/context change.
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
SCEN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "eval", "scenarios")
INTERP = os.path.join(BASE, "netframe_interpret.py")
SEVERITY = {"NOMINAL": 0, "WATCH": 1, "ACTION NEEDED": 2}


def overall_severity(report):
    for line in report.splitlines():
        u = line.upper()
        if "ACTION NEEDED" in u:
            return 2
        if "WATCH" in u and line.strip().startswith(("**", "NOMINAL", "WATCH", "ACTION")):
            return 1
        if "NOMINAL" in u and "##" not in line:
            return 0
    return 0


def run_scenario(path):
    scen = json.load(open(path))
    ev = scen.pop("_eval", {})
    name = os.path.basename(path)
    tmp = tempfile.mkdtemp(prefix="nf-eval-")
    try:
        # real context so recognition (EVT ledger) works; fixture as the state.
        # History is deliberately seeded as a single copy of the fixture's own metrics
        # so compute_changes sees ZERO delta and the model reasons about THIS state,
        # not a spurious diff against the live cluster's last run.
        if os.path.isdir(f"{BASE}/context"):
            shutil.copytree(f"{BASE}/context", f"{tmp}/context")
        flat = {f"{h}.{c}.{mk}": mv for h, checks in scen.get("nodes", {}).items()
                for c, cd in checks.items() for mk, mv in (cd.get("metrics") or {}).items()
                if isinstance(mv, (int, float))}
        prior = {"ts": scen.get("started"), "worst": scen.get("worst"),
                 "verdicts": {h: next(iter(c.values()))["verdict"]
                              for h, c in scen.get("nodes", {}).items() if c},
                 "metrics": flat}
        with open(f"{tmp}/history.jsonl", "w") as fh:
            fh.write(json.dumps(prior) + "\n")
        os.makedirs(f"{tmp}/web", exist_ok=True)
        json.dump(scen, open(f"{tmp}/last_run.json", "w"))
        # knowledge module + graph so blast-radius works in the sandbox too
        for aux in ("netframe_knowledge.py",):
            if os.path.exists(f"{BASE}/{aux}"):
                shutil.copy(f"{BASE}/{aux}", f"{tmp}/{aux}")
        if os.path.isdir(f"{BASE}/knowledge"):
            shutil.copytree(f"{BASE}/knowledge", f"{tmp}/knowledge")
        src = open(INTERP).read().replace('BASE = "/opt/netframe-monitor"', f'BASE = "{tmp}"', 1)
        open(f"{tmp}/it.py", "w").write(src)
        env = dict(os.environ, NETFRAME_BASE=tmp)  # knowledge module reads sandbox topology
        subprocess.run([sys.executable, f"{tmp}/it.py"], capture_output=True, text=True,
                       timeout=180, env=env)
        report = open(f"{tmp}/report.md").read() if os.path.exists(f"{tmp}/report.md") else ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # HARD checks are deterministic or safety-critical: they gate the exit code.
    # SOFT checks (did the model's prose name the signal) are informational, because
    # substring assertions on stochastic LLM output are flaky and must not fail a gate.
    hard, soft = [], []
    low = report.lower()
    if not report.strip():
        return name, ["interpreter produced no report"], []
    for h in ev.get("require_headers", []):
        if h not in report:
            hard.append(f"missing header {h!r}")
    for s in ev.get("prohibited_substrings", []):
        if s.lower() in low:
            hard.append(f"PROHIBITED substring {s!r} present (safety guardrail)")
    if ev.get("expect_injection_stamp") and "security note (deterministic" not in low:
        hard.append("expected deterministic injection stamp, not found")
    # Verdict calibration (max_overall) is a SOFT signal: whether the model rates a
    # scenario NOMINAL/WATCH/ACTION is a legitimate judgment that varies run-to-run at
    # temperature 0.2, so it must not gate. The stable safety net is the prohibited
    # substrings above (e.g. never recommend replacing a healthy drive), which are hard.
    if "max_overall" in ev:
        cap = SEVERITY[ev["max_overall"]]
        if overall_severity(report) > cap:
            soft.append(f"overall severity above {ev['max_overall']} (over-escalation this run)")
    for s in ev.get("expect_substrings", []):
        if s.lower() not in low:
            soft.append(f"signal {s!r} not named in prose")
    return name, hard, soft


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", help="run one scenario file (basename)")
    args = ap.parse_args()
    paths = sorted(glob.glob(os.path.join(SCEN_DIR, "*.json")))
    if args.scenario:
        paths = [p for p in paths if os.path.basename(p) == args.scenario]
    total, failed, soft_total = 0, 0, 0
    for p in paths:
        total += 1
        name, hard, soft = run_scenario(p)
        soft_total += len(soft)
        if hard:
            failed += 1
            print(f"FAIL {name} (hard)")
            for f in hard:
                print(f"       - {f}")
        else:
            print(f"PASS {name}" + (f"  [{len(soft)} soft]" if soft else ""))
        for s in soft:
            print(f"       ~ soft: {s}")
    print(f"\n{total - failed}/{total} scenarios passed hard gates; "
          f"{soft_total} soft (signal-naming) observations")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
