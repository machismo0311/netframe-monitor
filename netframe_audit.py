#!/usr/bin/env python3
"""NetFRAME immutable operational history (Phase 2 / JAR-12).

A hash-chained, tamper-EVIDENT append-only ledger with an independent tamper-RESISTANT
mirror to Loki. Every significant event (proposal, approval, rejection, execution,
recognized incident) is recorded with a timestamp, actor identity, and (for actions) a
before/after state. Each record commits to the hash of the previous record, so any edit,
reorder, or deletion anywhere in the file breaks the chain and `verify` reports exactly
where. The Loki copy is written at record time, so even a root edit of the local file
leaves an independent trail.

Pure stdlib. Loki shipping is best-effort and never blocks a record.

CLI:
  netframe_audit.py verify        # walk the chain, report integrity
  netframe_audit.py tail [-n N]   # last N records
"""
import datetime as dt
import getpass
import hashlib
import json
import os
import sys
import urllib.request

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
LEDGER = f"{BASE}/context/incident-history.jsonl"
LOKI_URL = os.environ.get("NETFRAME_LOKI_PUSH",
                          "http://192.168.10.183:3100/loki/api/v1/push")
LOKI_JOB = "netframe-audit"
GENESIS = "genesis"


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _actor():
    # the human behind the action if invoked under sudo, else the process owner
    return os.environ.get("SUDO_USER") or os.environ.get("NETFRAME_ACTOR") or getpass.getuser()


def _canonical(rec):
    """Stable serialization of a record EXCLUDING its own hash, for hashing."""
    return json.dumps({k: v for k, v in rec.items() if k != "hash"},
                      sort_keys=True, separators=(",", ":"))


def _hash(rec):
    return hashlib.sha256(_canonical(rec).encode()).hexdigest()


def _read():
    if not os.path.exists(LEDGER):
        return []
    out = []
    for line in open(LEDGER):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def _rechain(records):
    """Rebuild seq/prev_hash/hash over records in file order. Used to migrate any
    pre-chain records into the chain the first time we write."""
    prev = GENESIS
    for i, r in enumerate(records):
        r.pop("hash", None)
        r["seq"] = i
        r["prev_hash"] = prev
        r["hash"] = _hash(r)
        prev = r["hash"]
    return records


def _write(records):
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    with open(LEDGER, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def _ship_to_loki(rec):
    try:
        ns = str(int(dt.datetime.now(dt.timezone.utc).timestamp() * 1e9))
        payload = {"streams": [{"stream": {"job": LOKI_JOB, "event": str(rec.get("event"))},
                                "values": [[ns, json.dumps(rec)]]}]}
        req = urllib.request.Request(LOKI_URL, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=4).read()
        return True
    except Exception:  # noqa: BLE001 - the local chain is the source of truth; Loki is a mirror
        return False


def record(event, **fields):
    """Append a chained, actor-stamped record and mirror it to Loki. Returns the record."""
    records = _read()
    # migrate any legacy unchained records into the chain first
    if records and "hash" not in records[-1]:
        records = _rechain(records)
    prev = records[-1]["hash"] if records else GENESIS
    seq = (records[-1]["seq"] + 1) if records else 0
    rec = {"seq": seq, "ts": _now(), "actor": _actor(), "event": event, **fields,
           "prev_hash": prev}
    rec["hash"] = _hash(rec)
    records.append(rec)
    _write(records)
    rec["_loki"] = _ship_to_loki(rec)
    return rec


def verify():
    """Walk the chain. Returns (ok, message)."""
    records = _read()
    if not records:
        return True, "ledger empty"
    if "hash" not in records[0]:
        return False, "records are not chained (pre-Phase-2); run any record() to migrate"
    prev = GENESIS
    for r in records:
        if r.get("prev_hash") != prev:
            return False, f"chain break at seq {r.get('seq')}: prev_hash mismatch (record edited/removed)"
        if _hash(r) != r.get("hash"):
            return False, f"tamper at seq {r.get('seq')}: content does not match its hash"
        prev = r["hash"]
    return True, f"chain intact: {len(records)} records, head {prev[:12]}"


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    if cmd == "verify":
        ok, msg = verify()
        print(("OK: " if ok else "FAIL: ") + msg)
        sys.exit(0 if ok else 1)
    elif cmd == "tail":
        n = int(sys.argv[sys.argv.index("-n") + 1]) if "-n" in sys.argv else 20
        for r in _read()[-n:]:
            loki = ""
            print(f"  seq {r.get('seq'):>3} {r.get('ts', '')[:19]} {r.get('actor', '?'):<10} "
                  f"{r.get('event', ''):<16} {r.get('action', '')}{loki}")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
