#!/usr/bin/env python3
"""CI merge gate: merge a PR only on explicit, named check PASS (NF-AIOPS-004).

WHY THIS EXISTS
---------------
PR #37 was merged while its checks reported nothing: the wait-loop treated "no
checks reported" as completion, because it only waited while the word "pending"
was present. Absence of evidence became evidence of success. CI later passed on
main, so nothing broke - but the gate was luck, not enforcement.

THE STATE MODEL
---------------
    UNKNOWN  - no checks reported yet, or a required check has not appeared.
               UNKNOWN CANNOT MERGE. It can only wait, and on timeout it FAILS.
    PENDING  - required checks exist but have not completed. Wait.
    FAIL     - any required check failed, or timeout expired.
    PASS     - every required check is present, completed, and SUCCESS.
               Only this state merges.

There is no path from "nothing reported" to a merge. The default is refusal.

AUDITABILITY
------------
Before merging, the full decision record (every check name/state, the head SHA,
the decision, the timestamp) is posted as a PR comment, so the evidence the
merge was based on is permanently attached to the PR itself - not lost in a
terminal scrollback. If the comment cannot be posted, the merge does not happen.

Usage:
  tools/merge_gate.py <pr-number> [--repo owner/name]
      [--require "Python lint + syntax" --require "ShellCheck (bash)"]
      [--timeout 900] [--no-merge]   (--no-merge = validate + comment only)
"""
import argparse
import datetime as dt
import json
import subprocess
import sys
import time

DEFAULT_REQUIRED = ["Python lint + syntax", "ShellCheck (bash)"]
POLL_S = 15

PASS, FAIL, PENDING, UNKNOWN = "PASS", "FAIL", "PENDING", "UNKNOWN"
# conclusions that count as success for a completed run
SUCCESS_STATES = {"SUCCESS"}
FAILURE_STATES = {"FAILURE", "ERROR", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED",
                  "STARTUP_FAILURE"}


def decide(rollup, required):
    """Pure decision core -> (state, detail_dict). Deterministic and unit-testable.

    rollup: list of {"name"/"context", "status", "conclusion"/"state"} from GitHub.
    Duplicate entries per check name are normal (push + pull_request events both run);
    a check passes only if at least one instance succeeded AND no instance failed.
    """
    seen = {}
    for c in rollup or []:
        name = c.get("name") or c.get("context") or "?"
        concl = (c.get("conclusion") or c.get("state") or "").upper()
        status = (c.get("status") or "").upper()
        if status and status != "COMPLETED":
            state = PENDING
        elif concl in SUCCESS_STATES:
            state = PASS
        elif concl in FAILURE_STATES:
            state = FAIL
        else:
            state = PENDING
        # worst-wins per name: FAIL > PENDING > PASS
        rank = {FAIL: 2, PENDING: 1, PASS: 0}
        if name not in seen or rank[state] > rank[seen[name]]:
            seen[name] = state

    detail = {"reported": seen, "required": required}
    if not seen:
        return UNKNOWN, {**detail, "reason": "no checks reported"}
    missing = [r for r in required if r not in seen]
    if missing:
        return UNKNOWN, {**detail, "reason": f"required check(s) never reported: {missing}"}
    failed = [r for r in required if seen[r] == FAIL]
    if failed:
        return FAIL, {**detail, "reason": f"required check(s) failed: {failed}"}
    # a failure in ANY reported check refuses the merge, required or not
    other_failed = [n for n, s in seen.items() if s == FAIL]
    if other_failed:
        return FAIL, {**detail, "reason": f"non-required check(s) failed: {other_failed}"}
    pending = [n for n, s in seen.items() if s == PENDING]
    if pending:
        return PENDING, {**detail, "reason": f"still running: {pending}"}
    return PASS, {**detail, "reason": "all required checks passed explicitly"}


def _gh(args, repo=None):
    cmd = ["gh"] + args + (["--repo", repo] if repo else [])
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])}: {p.stderr.strip()[:200]}")
    return p.stdout


def fetch(pr, repo):
    out = _gh(["pr", "view", str(pr), "--json", "statusCheckRollup,headRefOid,title"],
              repo)
    d = json.loads(out)
    return d.get("statusCheckRollup") or [], d.get("headRefOid", "?"), d.get("title", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pr", type=int)
    ap.add_argument("--repo", default=None)
    ap.add_argument("--require", action="append", default=None)
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--no-merge", action="store_true")
    a = ap.parse_args()
    required = a.require or DEFAULT_REQUIRED

    deadline = time.time() + a.timeout
    state, detail, sha = UNKNOWN, {"reason": "not yet polled"}, "?"
    while time.time() < deadline:
        rollup, sha, _title = fetch(a.pr, a.repo)
        state, detail = decide(rollup, required)
        print(f"  [{dt.datetime.now(dt.timezone.utc):%H:%M:%S}] {state}: {detail['reason']}")
        if state in (PASS, FAIL):
            break
        time.sleep(POLL_S)
    else:
        # timeout: whatever we were waiting on never resolved. UNKNOWN/PENDING -> FAIL.
        state, detail = FAIL, {**detail,
                               "reason": f"timeout after {a.timeout}s in state {state}: "
                                         + detail.get("reason", "")}

    record = {"tool": "merge_gate", "pr": a.pr, "head_sha": sha, "decision": state,
              "required_checks": required, "checks_reported": detail.get("reported", {}),
              "reason": detail["reason"],
              "at": dt.datetime.now(dt.timezone.utc).isoformat()}
    body = ("### Merge-gate decision\n```json\n" + json.dumps(record, indent=2)
            + "\n```\n" + ("Merging: every required check passed explicitly."
                           if state == PASS and not a.no_merge else
                           "Not merging." if state != PASS else "Validation only (--no-merge)."))
    if state != PASS:
        print(f"REFUSED: {detail['reason']}", file=sys.stderr)
        try:
            _gh(["pr", "comment", str(a.pr), "--body", body], a.repo)
        except RuntimeError as e:
            print(f"  (refusal comment failed: {e})", file=sys.stderr)
        return 1
    # PASS: the audit comment must land BEFORE the merge, or the merge does not happen.
    _gh(["pr", "comment", str(a.pr), "--body", body], a.repo)
    if a.no_merge:
        print("PASS (validation only; --no-merge)")
        return 0
    _gh(["pr", "merge", str(a.pr), "--squash", "--delete-branch"], a.repo)
    print(f"MERGED #{a.pr} at {sha} with explicit PASS on: {', '.join(required)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
