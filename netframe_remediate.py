#!/usr/bin/env python3
"""NetFRAME gated remediation: Observe -> Recommend -> Request Approval -> Execute -> Document.

SAFETY MODEL (never autonomous):
  * Jarvis can ONLY ever execute actions in the ALLOWLIST below (small, safe, reversible,
    no data risk). Anything else is a Tier-2 production change that Jarvis NEVER executes;
    it only prints the approval workflow for a human to perform manually.
  * NOTHING executes without an explicit human 'approve <id>'. There is no auto-execute
    and no implied approval.
  * Every proposal, approval, rejection, and execution result is logged to the incident
    history (which is operational memory).

Tiers:
  Tier 0  observation only (the rest of netframe-monitor). No action here.
  Tier 1  safe automation: the ALLOWLIST. Executable ONLY after explicit approve.
  Tier 2  production changes (Proxmox/VM/network/firewall/DNS/storage/hardware/security/
          GitHub): NOT in the allowlist; 'propose' refuses and emits the approval workflow.

Usage:
  netframe_remediate.py catalog                    # list allowlisted (Tier 1) actions
  netframe_remediate.py propose <action_id> [--reason R] [--evidence E] [--confidence N]
  netframe_remediate.py list                        # pending proposals
  netframe_remediate.py approve <id> [--dry-run]    # THE human gate: execute
  netframe_remediate.py reject  <id> [--reason R]
  netframe_remediate.py history [-n N]
"""
import argparse
import datetime as dt
import json
import os
import subprocess

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
CONTEXT = f"{BASE}/context"
PENDING = f"{CONTEXT}/pending-remediation.jsonl"
HISTORY = f"{CONTEXT}/incident-history.jsonl"
EXEC_TIMEOUT = 180

# Tier-1 allowlist ONLY. Each action: safe, reversible, no data risk, with a known-good
# resolution. 'argv' is what runs on approve (list form, no shell). Add here deliberately.
ALLOWLIST = {
    "rerun-health-check": {
        "tier": 1,
        "desc": "Re-run the read-only cluster health sweep (a failed/transient check).",
        "why": "A transient check failure clears on the next read-only sweep; no state change.",
        "rollback": "None needed; the sweep is read-only.",
        "data_risk": "none",
        "argv": ["/usr/bin/bash", f"{BASE}/netframe-run.sh"],
    },
    "restart-report-web": {
        "tier": 1,
        "desc": "Restart the local NetFRAME health report web service on Jarvis.",
        "why": "Non-critical static web page; restart clears a hung server. Auto-restarts anyway.",
        "rollback": "systemctl start netframe-report-web (it auto-restarts on failure).",
        "data_risk": "none",
        "argv": ["/usr/bin/systemctl", "restart", "netframe-report-web"],
    },
    "restart-wazuh-indexer": {
        "tier": 1,
        "desc": "Restart wazuh-indexer inside VM104 (the EVT-004 known-good fix for a "
                "dashboard-503 / indexer-failed-while-manager-healthy state).",
        "why": "EVT-004: the indexer overruns its start timeout on boot; an in-place restart "
               "recovers it. NEVER power-cycle VM104.",
        "rollback": "None; restarting a failed indexer only moves it toward healthy.",
        "data_risk": "none (in-place service restart; power-cycle would risk corruption, so "
                     "this does NOT power-cycle).",
        # Executes via the quarkylab host + guest agent; requires that access to be wired.
        "argv": ["/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                 "root@192.168.10.179", "qm guest exec 104 -- systemctl restart wazuh-indexer"],
        "needs_access": "root SSH Jarvis->quarkylab (not the scoped monitor key).",
    },
}


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _log(rec):
    os.makedirs(CONTEXT, exist_ok=True)
    with open(HISTORY, "a") as fh:
        fh.write(json.dumps(rec) + "\n")


def _read(path):
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def _write_pending(items):
    with open(PENDING, "w") as fh:
        for r in items:
            fh.write(json.dumps(r) + "\n")


def cmd_catalog(_a):
    print("Tier-1 allowlist (executable ONLY after explicit approve):")
    for aid, a in ALLOWLIST.items():
        print(f"  {aid}: {a['desc']}")
        print(f"     why={a['why']}  data_risk={a['data_risk']}")
    print("\nTier-2 (production: Proxmox/VM/network/firewall/DNS/storage/hardware/security/"
          "GitHub) is NOT executable by Jarvis; it is described for manual human action.")


def cmd_propose(a):
    if a.action_id not in ALLOWLIST:
        print(f"REFUSED: '{a.action_id}' is not in the Tier-1 allowlist. If this is a real need, "
              f"it is a Tier-2 production change. Jarvis will NOT execute it. Approval workflow:\n"
              f"  Problem: {a.reason or '(state the problem)'}\n"
              f"  Evidence: {a.evidence or '(cite telemetry)'}\n"
              f"  Recommended action: {a.action_id} (manual, human-performed)\n"
              f"  Risk: production-affecting; assess before acting.\n"
              f"  Rollback: define before acting.\n"
              f"A human must decide and perform this manually.")
        _log({"ts": _now(), "event": "tier2-refused", "action": a.action_id,
              "reason": a.reason, "evidence": a.evidence})
        return
    act = ALLOWLIST[a.action_id]
    pend = _read(PENDING)
    pid = (max([p.get("id", 0) for p in pend]) + 1) if pend else 1
    rec = {"id": pid, "proposed": _now(), "action": a.action_id, "tier": act["tier"],
           "reason": a.reason or "", "evidence": a.evidence or "",
           "confidence": a.confidence, "rollback": act["rollback"]}
    pend.append(rec)
    _write_pending(pend)
    _log({"ts": _now(), "event": "proposed", **rec})
    print(f"PROPOSAL #{pid} ({a.action_id}, Tier {act['tier']}) -- awaiting explicit human approval\n"
          f"  Problem: {a.reason or '(none given)'}\n"
          f"  Evidence: {a.evidence or '(none given)'}\n"
          f"  Recommended action: {act['desc']}\n"
          f"  Confidence: {a.confidence}%  (needs >=95 for Tier 1)\n"
          f"  Impact/data risk: {act['data_risk']}\n"
          f"  Rollback: {act['rollback']}\n"
          f"Approve with: netframe_remediate.py approve {pid}   (or reject {pid})")


def cmd_list(_a):
    pend = _read(PENDING)
    if not pend:
        print("(no pending remediation proposals)")
        return
    for p in pend:
        print(f"  #{p['id']} {p['action']} (Tier {p['tier']}, conf {p.get('confidence')}%): "
              f"{p.get('reason', '')}")


def cmd_approve(a):
    pend = _read(PENDING)
    match = [p for p in pend if p["id"] == a.id]
    if not match:
        print(f"no pending proposal #{a.id}")
        return
    p = match[0]
    act = ALLOWLIST.get(p["action"])
    if not act:
        print("action no longer in allowlist; refusing.")
        return
    if (p.get("confidence") or 0) < 95:
        print(f"BLOCKED: confidence {p.get('confidence')}% < 95% required for Tier-1 execution.")
        return
    if a.dry_run:
        print(f"DRY-RUN #{a.id} {p['action']}: would run {act['argv']}")
        return
    print(f"EXECUTING approved #{a.id} {p['action']}: {act['argv']}")
    try:
        r = subprocess.run(act["argv"], capture_output=True, text=True, timeout=EXEC_TIMEOUT)
        result = {"rc": r.returncode, "stdout": r.stdout[-500:], "stderr": r.stderr[-500:]}
        ok = r.returncode == 0
    except Exception as e:  # noqa: BLE001
        result, ok = {"error": str(e)}, False
    _log({"ts": _now(), "event": "executed", "id": a.id, "action": p["action"],
          "tier": p["tier"], "approved_by": "human (explicit)", "ok": ok, "result": result})
    _write_pending([x for x in pend if x["id"] != a.id])
    print(f"RESULT: {'SUCCESS' if ok else 'FAILED'} (rc={result.get('rc')}). Recorded in incident history.")
    if not ok:
        print(f"  rollback if needed: {act['rollback']}")


def cmd_reject(a):
    pend = _read(PENDING)
    match = [p for p in pend if p["id"] == a.id]
    if not match:
        print(f"no pending proposal #{a.id}")
        return
    _log({"ts": _now(), "event": "rejected", "id": a.id, "action": match[0]["action"],
          "reason": a.reason or ""})
    _write_pending([x for x in pend if x["id"] != a.id])
    print(f"rejected #{a.id}; recorded in incident history (rejected actions are memory too).")


def cmd_history(a):
    hist = _read(HISTORY)[-a.n:]
    if not hist:
        print("(no incident history yet)")
        return
    for h in hist:
        print(f"  {h['ts'][:19]} {h['event']:14} {h.get('action', '')} "
              f"{('ok=' + str(h.get('ok'))) if 'ok' in h else ''}")


def main():
    p = argparse.ArgumentParser(description="NetFRAME gated remediation (human-in-the-loop).")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("catalog").set_defaults(func=cmd_catalog)
    pr = sub.add_parser("propose")
    pr.add_argument("action_id")
    pr.add_argument("--reason")
    pr.add_argument("--evidence")
    pr.add_argument("--confidence", type=int, default=0)
    pr.set_defaults(func=cmd_propose)
    sub.add_parser("list").set_defaults(func=cmd_list)
    ap = sub.add_parser("approve")
    ap.add_argument("id", type=int)
    ap.add_argument("--dry-run", action="store_true")
    ap.set_defaults(func=cmd_approve)
    rj = sub.add_parser("reject")
    rj.add_argument("id", type=int)
    rj.add_argument("--reason")
    rj.set_defaults(func=cmd_reject)
    hi = sub.add_parser("history")
    hi.add_argument("-n", type=int, default=20)
    hi.set_defaults(func=cmd_history)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
