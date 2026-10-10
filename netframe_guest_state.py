"""NetFRAME guest_state: hypervisor guest state per Proxmox node, keyed by VMID.

Classifies one document from the node-local wrapper (node-local/pve-nfm-guests, installed as
/usr/local/sbin/nfm-guests) against the tracked inventory (node-local/pve-expected-guests.psv).
Pure functions: no I/O except load_inventory().

SCOPE. This is INFRASTRUCTURE CONTEXT ONLY. A guest that is RUNNING means the hypervisor reports the
container or VM as running. It never means the application inside (Headscale, Home Assistant,
Minecraft, ...) is NOMINAL, and nothing here derives a service or application field from it. The
service-health probes remain the authority for applications. Guest state is also never inferred from
an application probe, ICMP, TCP, or from the inventory alone: only from the wrapper's measurement.

WHY A NEW CHECK NAME. The live wall dashboard merges every node's checks["guests"]["metrics"]["guests"]
({name: status}) and paints a running guest green. This check is deliberately called `guest_state`
and uses a different shape, so adding a node here cannot turn an application tile green from guest
state alone.

Per-guest state vocabulary
--------------------------
RUNNING   lxc status running; qemu status running AND qmpstatus running.
STOPPED   status stopped (either type).
PAUSED    qemu qmpstatus paused, suspended or prelaunch: the VM process exists but its vCPUs are not
          executing (paused by an operator or a backup, suspended to RAM/disk, or created but never
          started). `qm list` shows all three as `running`, which is why the wrapper uses pvesh.
MISSING   expected in the inventory, absent from a SUCCESSFUL collection. Never inferred from a
          failed, stale or empty collection.
UNKNOWN   anything else: an unrecognised status or qmpstatus (io-error, guest-panicked, inmigrate,
          ...), a qemu guest without a qmpstatus (running-vs-paused cannot be told apart), or every
          expected guest when the collection itself cannot be trusted. The raw values stay visible.

Node-level collection state
---------------------------
OK                 a well-formed, current document for this node.
COLLECTION_FAILED  nonzero exit, ok=false, empty, non-JSON, wrong schema, wrong node, malformed
                   guest entry or duplicate VMID.
STALE              collected_at older than MAX_AGE_S, or more than CLOCK_SLACK_S in the future.
ZERO_UNEXPECTED    a successful collection returned zero guests while the inventory expects some.
                   Treated as a collection anomaly: every expected guest is UNKNOWN, never MISSING.

Verdict
-------
UNKNOWN  collection COLLECTION_FAILED, STALE or ZERO_UNEXPECTED; the inventory unreadable or holding
         no rows for this node; or (with no measured fault) an expected guest UNKNOWN, or an
         expected guest stopped/paused whose onboot could not be read. Never OK, and never a WARN
         that pretends to be a measurement.
WARN     an expected guest MISSING; an expected guest with onboot=1 that is STOPPED or PAUSED.
OK       every expected guest measured, and none of the above.

An expected guest with onboot=0 that is stopped or paused is never alerted: onboot is PVE's own,
measured statement of whether the guest should be running, so nothing is guessed. Extra guests (not
in the inventory) and renames (same VMID, different name) are always listed, never discarded, and do
not change the verdict: they are inventory drift for a human to review, not an outage.

The generic monitor path keeps its more specific verdicts (TIMEOUT, AUTH-FAIL, UNREACHABLE) for an
ssh-level failure; this module then still reports collection COLLECTION_FAILED in the metrics.
"""
import json

SCHEMA = "netframe-guest-state/v1"

RUNNING, STOPPED, PAUSED, MISSING, UNKNOWN = "RUNNING", "STOPPED", "PAUSED", "MISSING", "UNKNOWN"
GUEST_STATES = (RUNNING, STOPPED, PAUSED, MISSING, UNKNOWN)

OK, COLLECTION_FAILED, STALE, ZERO_UNEXPECTED = "OK", "COLLECTION_FAILED", "STALE", "ZERO_UNEXPECTED"
COLLECTION_STATES = (OK, COLLECTION_FAILED, STALE, ZERO_UNEXPECTED)

#: qemu qmpstatus values that mean the VM exists but its vCPUs are not running.
PAUSED_QMP = ("paused", "suspended", "prelaunch")

#: Clock slack, same figure the journal_errors window uses (collection time plus modest skew).
CLOCK_SLACK_S = 300
#: The wrapper stamps collected_at when the monitor invokes it, and the monitor bounds every check at
#: CHECK_TIMEOUT (120 s). A document older than that bound plus the clock slack cannot be this run's
#: measurement: it is a replayed or cached document, or a clock is wrong. 420 s is still well under
#: the 15-minute collection cadence, so one stale document can never be mistaken for the next run.
CHECK_TIMEOUT_S = 120
MAX_AGE_S = CHECK_TIMEOUT_S + CLOCK_SLACK_S

#: Bounded reason vocabulary (fits check_reason()'s [A-Z0-9_]{,32}).
REASONS = ("COLLECTION_FAILED", "STALE", "ZERO_UNEXPECTED", "INVENTORY_UNREADABLE",
           "NO_INVENTORY_FOR_NODE", "EXPECTED_GUEST_MISSING", "EXPECTED_GUEST_STOPPED",
           "EXPECTED_GUEST_PAUSED", "ONBOOT_UNMEASURED", "GUEST_STATE_UNKNOWN")

SEMANTICS = "hypervisor guest state only; RUNNING is infrastructure context, not application health"

_INV_FIELDS = ("node", "vmid", "type", "name", "notes")


def load_inventory(path):
    """The tracked inventory as {node: {vmid(int): {"type", "name"}}}. Raises on a malformed file."""
    inv, header, rows = {}, None, 0
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if header is None:
                if tuple(parts) != _INV_FIELDS:
                    raise ValueError(f"inventory header must be {'|'.join(_INV_FIELDS)}")
                header = parts
                continue
            if len(parts) != len(header):
                raise ValueError(f"inventory row has {len(parts)} fields, header has {len(header)}")
            r = dict(zip(header, parts))
            if not r["vmid"].isdigit() or int(r["vmid"]) <= 0:
                raise ValueError(f"inventory vmid not a positive integer: {r['vmid']!r}")
            if r["type"] not in ("lxc", "qemu"):
                raise ValueError(f"inventory type must be lxc or qemu: {r['type']!r}")
            if not r["node"] or not r["name"]:
                raise ValueError("inventory node and name must be non-empty")
            node, vmid = r["node"], int(r["vmid"])
            if vmid in inv.get(node, {}):
                raise ValueError(f"duplicate inventory entry {node}/{vmid}")
            inv.setdefault(node, {})[vmid] = {"type": r["type"], "name": r["name"]}
            rows += 1
    if not rows:
        raise ValueError("inventory is empty")
    return inv


def guest_state(g):
    """Normalized state of one observed guest (see the module docstring for the mapping)."""
    status = g.get("status")
    if status == "stopped":
        return STOPPED
    if g.get("type") == "lxc":
        return RUNNING if status == "running" else UNKNOWN
    qmp = g.get("qmpstatus")
    if status == "running":
        if qmp == "running":
            return RUNNING
        if qmp in PAUSED_QMP:
            return PAUSED
        return UNKNOWN
    if status in PAUSED_QMP or qmp in PAUSED_QMP:
        return PAUSED
    return UNKNOWN


def _load_doc(out, rc, host):
    """(doc, guests, error_token). doc/guests are None when the collection cannot be trusted."""
    if not out or not out.strip():
        return None, None, "NONZERO_EXIT" if rc != 0 else "EMPTY"
    try:
        doc = json.loads(out)
    except ValueError:
        # Nonzero exit with text that is not JSON is ssh/sudo failure text, not a document.
        return None, None, "NONZERO_EXIT" if rc != 0 else "NOT_JSON"
    if not isinstance(doc, dict):
        return None, None, "MALFORMED"
    if doc.get("schema") != SCHEMA:
        return doc, None, "WRONG_SCHEMA"
    if host is None or doc.get("node") != host:
        return doc, None, "WRONG_NODE"
    if doc.get("ok") is not True or rc != 0:
        err = doc.get("error")
        token = err if isinstance(err, str) and err.replace("_", "").isalnum() else "WRAPPER_FAILED"
        return doc, None, token[:32]
    raw = doc.get("guests")
    if not isinstance(raw, list):
        return doc, None, "MALFORMED"
    guests = {}
    for g in raw:
        if not isinstance(g, dict) or type(g.get("vmid")) is not int or g.get("type") not in ("lxc", "qemu") \
                or not isinstance(g.get("status"), str) or not isinstance(g.get("name"), str):
            return doc, None, "MALFORMED"
        if g["vmid"] in guests:
            return doc, None, "DUPLICATE_VMID"
        guests[g["vmid"]] = g
    return doc, guests, None


def evaluate(out, rc=0, host=None, now=0, inventory=None):
    """The guest_state metrics, including `verdict` and `reason`, for one wrapper run on `host`.

    `inventory` is load_inventory()'s result, or None when it could not be read.
    """
    doc, observed, error = _load_doc(out, rc, host)
    d = doc if isinstance(doc, dict) else {}
    m = {"schema": d.get("schema"), "node": d.get("node"),
         "collected_at": None, "age_s": None, "collection": OK, "collection_error": None,
         "inventory": "OK", "guests": {}, "counts": {s: 0 for s in GUEST_STATES},
         "missing": [], "extra": [], "renamed": [], "retyped": [], "semantics": SEMANTICS,
         "verdict": "UNKNOWN", "reason": ""}
    ts = d.get("collected_at")
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        m["collected_at"] = int(ts)
        m["age_s"] = int(now - ts)
    if observed is None:
        m["collection"], m["collection_error"] = COLLECTION_FAILED, error
    elif m["collected_at"] is None:
        m["collection"], m["collection_error"] = COLLECTION_FAILED, "NO_TIMESTAMP"
        observed = None
    elif m["age_s"] > MAX_AGE_S or m["age_s"] < -CLOCK_SLACK_S:
        m["collection"] = STALE
        observed = None

    if inventory is None:
        m["inventory"] = "UNREADABLE"
        expected = {}
    else:
        expected = inventory.get(host or "", {})
        if not expected:
            m["inventory"] = "NONE_FOR_NODE"
    if observed is not None and not observed and expected:
        m["collection"] = ZERO_UNEXPECTED
        observed = None

    guests = m["guests"]
    for vmid, exp in sorted(expected.items()):
        guests[str(vmid)] = {"name": exp["name"], "type": exp["type"], "state": UNKNOWN,
                             "raw_status": None, "qmpstatus": None, "lock": None, "onboot": None,
                             "expected": True, "expected_name": exp["name"]}
    if observed is not None:
        for vmid, g in sorted(observed.items()):
            exp = expected.get(vmid)
            onb = g.get("onboot")
            entry = {"name": g["name"], "type": g["type"], "state": guest_state(g),
                     "raw_status": g["status"],
                     "qmpstatus": g.get("qmpstatus") if isinstance(g.get("qmpstatus"), str) else None,
                     "lock": g.get("lock") if isinstance(g.get("lock"), str) else None,
                     "onboot": onb if onb in (0, 1) and not isinstance(onb, bool) else None,
                     "expected": exp is not None,
                     "expected_name": exp["name"] if exp else None}
            guests[str(vmid)] = entry
            if exp is None:
                m["extra"].append({"vmid": vmid, "name": g["name"], "type": g["type"],
                                   "state": entry["state"]})
                continue
            if g["name"] != exp["name"]:
                m["renamed"].append({"vmid": vmid, "expected_name": exp["name"],
                                     "observed_name": g["name"]})
            if g["type"] != exp["type"]:
                m["retyped"].append({"vmid": vmid, "expected_type": exp["type"],
                                     "observed_type": g["type"]})
        for vmid in sorted(expected):
            if vmid not in observed:
                guests[str(vmid)]["state"] = MISSING
                m["missing"].append(vmid)
    for g in guests.values():
        m["counts"][g["state"]] += 1

    m["verdict"], m["reason"] = _verdict(m)
    return m


def _verdict(m):
    if m["collection"] != OK:
        return "UNKNOWN", m["collection"]
    if m["inventory"] == "UNREADABLE":
        return "UNKNOWN", "INVENTORY_UNREADABLE"
    if m["inventory"] == "NONE_FOR_NODE":
        return "UNKNOWN", "NO_INVENTORY_FOR_NODE"
    warn, unknown = None, None
    for g in (g for g in m["guests"].values() if g["expected"]):
        st = g["state"]
        if st == MISSING:
            warn = warn or "EXPECTED_GUEST_MISSING"
        elif st in (STOPPED, PAUSED):
            if g["onboot"] == 1:
                warn = warn or ("EXPECTED_GUEST_STOPPED" if st == STOPPED else "EXPECTED_GUEST_PAUSED")
            elif g["onboot"] is None:
                unknown = unknown or "ONBOOT_UNMEASURED"
        elif st == UNKNOWN:
            unknown = unknown or "GUEST_STATE_UNKNOWN"
    # A measured fault outranks an unmeasured guest: both are non-OK, and WARN names the action.
    if warn:
        return "WARN", warn
    if unknown:
        return "UNKNOWN", unknown
    return "OK", ""


def flat(m, prefix):
    """Trend values for history.jsonl. Counts only when the collection was trusted: a placeholder
    UNKNOWN for an unmeasured guest is not an observation, and writing 0 running for a failed
    collection would make "could not look" read as "everything is down" in every trend."""
    out = {f"{prefix}.collection_ok": 1 if m.get("collection") == OK else 0}
    if m.get("collection") == OK:
        for s in GUEST_STATES:
            out[f"{prefix}.{s.lower()}"] = (m.get("counts") or {}).get(s, 0)
        out[f"{prefix}.extra"] = len(m.get("extra") or [])
        out[f"{prefix}.renamed"] = len(m.get("renamed") or [])
    if m.get("age_s") is not None:
        out[f"{prefix}.age_s"] = m["age_s"]
    return out
