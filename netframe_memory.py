#!/usr/bin/env python3
"""NetFRAME operational memory: controlled, human-gated knowledge accumulation.

Design (per the AIOps brief: 'never blindly retrain, use controlled accumulation,
user-approved decisions'):
  - PROPOSE writes a candidate event to context/pending-memory.jsonl, which the
    interpreter does NOT read (not a .md). Jarvis or the operator may propose.
  - PROMOTE (an explicit human action) formats approved candidates as EVT-NNN
    blocks and appends them to context/30-known-events.md, which the interpreter
    DOES read. Only promoted memory influences reasoning.
Nothing here retrains any model; it curates the standing-context ledger.

Usage:
  netframe_memory.py propose --title T --systems S --signature SIG --cause C \\
      --resolution R --lesson L [--when W] [--evidence E]
  netframe_memory.py list-pending
  netframe_memory.py promote (all | <index>...)
  netframe_memory.py list
"""
import argparse
import datetime as dt
import json
import os
import re

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
CONTEXT = f"{BASE}/context"
LEDGER = f"{CONTEXT}/30-known-events.md"
PENDING = f"{CONTEXT}/pending-memory.jsonl"


def _now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")


def _next_evt_num():
    if not os.path.exists(LEDGER):
        return 1
    nums = [int(m.group(1)) for m in re.finditer(r"EVT-(\d{3})", open(LEDGER).read())]
    return (max(nums) + 1) if nums else 1


def _read_pending():
    if not os.path.exists(PENDING):
        return []
    out = []
    for line in open(PENDING):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def cmd_propose(a):
    rec = {
        "proposed": dt.datetime.now(dt.timezone.utc).isoformat(),
        "title": a.title, "when": a.when or _now(), "systems": a.systems,
        "evidence": a.evidence or "", "signature": a.signature,
        "cause": a.cause, "resolution": a.resolution, "lesson": a.lesson,
    }
    os.makedirs(CONTEXT, exist_ok=True)
    with open(PENDING, "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    print(f"proposed (pending human review): {a.title}\n"
          f"review with: netframe_memory.py list-pending ; promote with: promote <index>")


def cmd_list_pending(_a):
    p = _read_pending()
    if not p:
        print("(no pending proposals)")
        return
    for i, r in enumerate(p):
        print(f"[{i}] {r['title']}  (proposed {r['proposed'][:10]})")
        print(f"     signature: {r['signature']}")


def _fmt_block(num, r):
    lines = [f"\n## EVT-{num:03d} {r['title']}",
             f"- **When:** {r.get('when', '')}.",
             f"- **Systems:** {r.get('systems', '')}.",
             f"- **Signature:** {r.get('signature', '')}"]
    if r.get("evidence"):
        lines.append(f"- **Evidence:** {r['evidence']}")
    lines += [f"- **Root cause:** {r.get('cause', '')}",
              f"- **Resolution:** {r.get('resolution', '')}",
              f"- **Lesson:** {r.get('lesson', '')}"]
    return "\n".join(lines) + "\n"


def cmd_promote(a):
    pend = _read_pending()
    if not pend:
        print("(nothing pending to promote)")
        return
    if a.which == ["all"]:
        idxs = list(range(len(pend)))
    else:
        idxs = sorted({int(x) for x in a.which})
    promoted, num = [], _next_evt_num()
    with open(LEDGER, "a") as fh:
        for i in idxs:
            if 0 <= i < len(pend):
                fh.write(_fmt_block(num, pend[i]))
                promoted.append(i)
                print(f"promoted -> EVT-{num:03d} {pend[i]['title']}")
                num += 1
    # rewrite pending without the promoted ones
    remaining = [r for j, r in enumerate(pend) if j not in promoted]
    with open(PENDING, "w") as fh:
        for r in remaining:
            fh.write(json.dumps(r) + "\n")
    print(f"{len(promoted)} promoted into the ledger; {len(remaining)} still pending.")


def cmd_list(_a):
    if not os.path.exists(LEDGER):
        print("(no ledger yet)")
        return
    for m in re.finditer(r"^## (EVT-\d{3} .+)$", open(LEDGER).read(), re.M):
        print(" ", m.group(1))


def main():
    p = argparse.ArgumentParser(description="NetFRAME operational memory (human-gated).")
    sub = p.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("propose")
    for f in ("title", "systems", "signature", "cause", "resolution", "lesson"):
        pr.add_argument(f"--{f}", required=True)
    pr.add_argument("--when")
    pr.add_argument("--evidence")
    pr.set_defaults(func=cmd_propose)
    sub.add_parser("list-pending").set_defaults(func=cmd_list_pending)
    pm = sub.add_parser("promote")
    pm.add_argument("which", nargs="+", help="'all' or one or more pending indices")
    pm.set_defaults(func=cmd_promote)
    sub.add_parser("list").set_defaults(func=cmd_list)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
