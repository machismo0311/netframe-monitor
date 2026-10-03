"""Truthful Wazuh SIEM health (Packet C): seven measured inputs, two trees, one overall state.

WHY THIS EXISTS. From 2026-09-24 to 2026-10-02 the wall read "Wazuh SIEM = CORE OK" in green while
the indexer was down, the dashboard returned 503, Filebeat could not ship, and auth telemetry had
stopped on 8 of 9 Linux agents. The old check asked one question, "are the manager daemons
running", and its answer was presented as the health of the whole SIEM.

This module classifies the facts reported by the argument-free wrapper `nfm-wazuh-health`
(node-local/azuh-nfm-wazuh-health) into seven inputs:

    M manager   I indexer   D dashboard   F Filebeat   A agents   T auth telemetry   X drops

Each input is NOMINAL, DEGRADED, CRITICAL or UNKNOWN. Two trees aggregate them:

    services  = worst(M, I, D, F)      is the SIEM working
    integrity = worst(A, T, X)         can it see the estate

and the overall state is the worse of the two. Aggregation order is CRITICAL > DEGRADED > UNKNOWN >
NOMINAL. A measured fault always shows even when another input is unmeasured; NOMINAL needs all of
its inputs MEASURED nominal. UNKNOWN is never green.

A3-AWARE INDEXER TIMING (measured 2026-10-03, one VM 104 reboot): a normal cold start took 242.2 s
from start request to READY, and 11 min 25 s from READY to GREEN. So RED right after READY is
expected shard recovery, not an outage. The allowance is the A3 hard-stop criterion, 900 s after
READY, and is deliberately not longer than that evidence.

Pure functions only: no I/O except load_expected(). The monitor feeds in the previous run's
counters for the drop deltas.
"""
import re

SCHEMA = "netframe-wazuh-health/v1"

NOMINAL, DEGRADED, CRITICAL, UNKNOWN = "NOMINAL", "DEGRADED", "CRITICAL", "UNKNOWN"
STATES = (NOMINAL, DEGRADED, CRITICAL, UNKNOWN)
#: Aggregation precedence. UNKNOWN ranks above NOMINAL, so an unmeasured input can never read green.
SEVERITY = {NOMINAL: 0, UNKNOWN: 1, DEGRADED: 2, CRITICAL: 3}
#: The monitor's verdict vocabulary for each state.
VERDICT = {NOMINAL: "OK", DEGRADED: "WARN", CRITICAL: "CRIT", UNKNOWN: "UNKNOWN"}

INPUTS = ("M", "I", "D", "F", "A", "T", "X")
SERVICES, INTEGRITY = ("M", "I", "D", "F"), ("A", "T", "X")
INPUT_NAME = {"M": "manager", "I": "indexer", "D": "dashboard", "F": "filebeat",
              "A": "agents", "T": "auth", "X": "drops"}

# --- thresholds, each tied to its evidence ---------------------------------------------------
#: A3 hard stop: RED for 15 min after READY. Measured recovery after a cold start: 685 s.
INDEXER_RED_RECOVERY_S = 900
#: A3 margin: a start above 300 s used more than 71% of the 420 s budget (measured cold start 242 s).
INDEXER_SLOW_START_S = 300
#: The longest the A3 policy can legitimately be starting: two attempts of 420 s plus 30 s each.
#: Longer than this in one activating spell means the notifier keeps extending a start that never
#: becomes ready.
INDEXER_STUCK_ACTIVATING_S = 900
#: Stops took 24-26 s (2026-09-24, 2026-10-03). A stop that has not finished in 10 min is stuck.
INDEXER_STUCK_DEACTIVATING_S = 600
#: Largest gap between written alerts, Sep 25 to Oct 2: 3.96 h. Recalibrate on a healthy baseline.
OUTPUT_DEGRADED_S, OUTPUT_CRITICAL_S = 6 * 3600, 24 * 3600
FILEBEAT_LAG_BYTES = 1024 * 1024
FILEBEAT_NOT_SHIPPING_S = 24 * 3600
QUEUE_DEGRADED, QUEUE_CRITICAL = 0.70, 0.95
DROP_RATIO_CRITICAL = 0.01

MANAGER_TIER1 = ("analysisd", "remoted", "db")
MANAGER_TIER2 = ("modulesd", "logcollector", "syscheckd", "monitord", "execd", "authd", "apid")
#: Legacy name set, kept so consumers of `core_down` (netframe_evidence) keep working.
CORE_DAEMONS = ("analysisd", "remoted", "db", "modulesd", "syscheckd")

_KV = re.compile(r"^([a-z0-9_.]+)=([A-Za-z0-9_./:-]*)$")


def parse_kv(out):
    """The wrapper's key=value lines. Anything else is ignored, so stray text cannot inject a key."""
    kv = {}
    for line in (out or "").splitlines():
        m = _KV.match(line.strip())
        if m:
            kv[m.group(1)] = m.group(2)
    return kv


def _int(kv, key, default=None):
    v = kv.get(key)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _float(kv, key, default=None):
    v = kv.get(key)
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def worst(states):
    states = [s for s in states if s in SEVERITY]
    return max(states, key=lambda s: SEVERITY[s]) if states else UNKNOWN


def _input(state, *reasons, **details):
    return {"state": state, "reasons": [r for r in reasons if r], **details}


def load_expected(path):
    """The tracked expected-agents list (wazuh-expected-agents.psv). Raises on a malformed file."""
    rows, header = [], None
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if header is None:
                header = parts
                continue
            if len(parts) != len(header):
                raise ValueError(f"expected-agents row has {len(parts)} fields, header has {len(header)}")
            r = dict(zip(header, parts))
            rows.append({"id": r["id"], "name": r["name"], "required": r["required"] == "yes",
                         "auth": r["auth"], "canary": r["canary"] == "yes",
                         "auth_s": int(r["auth_h"]) * 3600})
    if not rows:
        raise ValueError("expected-agents list is empty")
    return rows


# --- M ---------------------------------------------------------------------------------------
def manager(kv, now):
    unit = kv.get("mgr.unit")
    daemons = {k[len("mgr.daemon."):]: v for k, v in kv.items() if k.startswith("mgr.daemon.")}
    if unit is None or not daemons:
        return _input(UNKNOWN, "MANAGER_UNMEASURED", core_down=[])
    core_down = sorted(f"wazuh-{d}" for d in CORE_DAEMONS if daemons.get(d) != "running")
    if unit != "active":
        return _input(CRITICAL, "MANAGER_DOWN", core_down=core_down)
    reasons, state = [], NOMINAL
    if any(daemons.get(d) != "running" for d in MANAGER_TIER1):
        reasons.append("CORE_DAEMON_DOWN")
        state = CRITICAL
    elif any(daemons.get(d) != "running" for d in MANAGER_TIER2):
        reasons.append("DAEMON_DOWN")
        state = DEGRADED
    if kv.get("mgr.api_http") not in ("401", "200"):
        reasons.append("API_DOWN")
        state = worst([state, DEGRADED])
    mtime = _int(kv, "mgr.alerts_mtime")
    if mtime is None:
        reasons.append("OUTPUT_UNMEASURED")
        state = worst([state, UNKNOWN])
    else:
        age = now - mtime
        if age > OUTPUT_CRITICAL_S:
            reasons.append("OUTPUT_STOPPED")
            state = CRITICAL
        elif age > OUTPUT_DEGRADED_S:
            reasons.append("OUTPUT_STALE")
            state = worst([state, DEGRADED])
    return _input(state, *reasons, core_down=core_down, alerts_mtime=mtime)


# --- I ---------------------------------------------------------------------------------------
def indexer(kv, now):
    """The indexer's state, aware of A3: starting and post-READY shard recovery are transient."""
    unit = kv.get("idx.unit")
    if unit is None:
        return _input(UNKNOWN, "INDEXER_UNMEASURED", phase="unknown")
    result = kv.get("idx.result")
    nrestarts = _int(kv, "idx.nrestarts", 0)
    exec_start = _int(kv, "idx.exec_start", 0)
    active_enter = _int(kv, "idx.active_enter", 0)
    state_change = _int(kv, "idx.state_change", 0)
    start_limit = result == "start-limit-hit" or (_int(kv, "idx.boot_start_limit", 0) or 0) > 0
    retried = nrestarts > 0 or (_int(kv, "idx.boot_sched_restarts", 0) or 0) > 0
    d = {"nrestarts": nrestarts, "start_limit": start_limit, "retried": retried,
         "start_duration_s": None, "activating_s": 0, "red_s": 0, "ready_at": active_enter or None}

    if unit == "failed":
        extra = ("INDEXER_START_LIMIT" if start_limit
                 else "INDEXER_START_TIMEOUT" if result == "timeout" else None)
        return _input(CRITICAL, "INDEXER_FAILED", extra, phase="failed", **d)
    if unit in ("inactive", "dead"):
        return _input(CRITICAL, "INDEXER_DOWN", phase="down", **d)
    if unit in ("activating", "reloading"):
        since = state_change or exec_start
        d["activating_s"] = max(0, now - since) if since else 0
        if since and d["activating_s"] > INDEXER_STUCK_ACTIVATING_S:
            return _input(CRITICAL, "INDEXER_STUCK_ACTIVATING", phase="stuck_activating", **d)
        return _input(DEGRADED, "INDEXER_STARTING", "INDEXER_START_RETRIED" if retried else None,
                      phase="starting", **d)
    if unit == "deactivating":
        stopping = max(0, now - state_change) if state_change else 0
        if state_change and stopping > INDEXER_STUCK_DEACTIVATING_S:
            return _input(CRITICAL, "INDEXER_STUCK_DEACTIVATING", phase="stuck_deactivating", **d)
        return _input(DEGRADED, "INDEXER_STOPPING", phase="stopping", **d)
    if unit != "active":
        return _input(UNKNOWN, "INDEXER_UNMEASURED", phase="unknown", **d)

    # Active (READY was sent). How long ago, how long the start took, and what the cluster says.
    ready_age = now - active_enter if active_enter else None
    if exec_start and active_enter and active_enter >= exec_start:
        d["start_duration_s"] = active_enter - exec_start
    in_recovery = ready_age is not None and ready_age <= INDEXER_RED_RECOVERY_S
    reasons, state, phase = [], NOMINAL, "ready"
    if d["start_duration_s"] is not None and d["start_duration_s"] > INDEXER_SLOW_START_S:
        reasons.append("INDEXER_SLOW_START")
        state = DEGRADED
    if retried:
        reasons.append("INDEXER_START_RETRIED")
        state = DEGRADED

    http = kv.get("idx.http")
    health = kv.get("idx.health", "unknown")
    if http not in ("401", "200"):
        # Right after READY the security plugin can still answer 503 while shards recover.
        if in_recovery:
            return _input(DEGRADED, "INDEXER_RECOVERING", *reasons, phase="recovering", **d)
        return _input(CRITICAL, "INDEXER_NOT_SERVING", *reasons, phase="not_serving", **d)
    if health == "green":
        return _input(state, *reasons, phase=phase, **d)
    if health == "yellow":
        return _input(worst([state, DEGRADED]), "INDEXER_YELLOW", *reasons, phase=phase, **d)
    if health == "red":
        # RED since when? The last logged transition to RED after READY, otherwise READY itself:
        # a node comes up RED and only logs the change AWAY from it.
        change_at, change_to = _int(kv, "idx.health_change_at", 0), kv.get("idx.health_change_to")
        red_since = active_enter
        if change_to == "red" and change_at and change_at >= (active_enter or 0):
            red_since = change_at
        d["red_s"] = max(0, now - red_since) if red_since else 0
        after_ready = red_since == active_enter
        if after_ready and red_since and d["red_s"] <= INDEXER_RED_RECOVERY_S:
            return _input(DEGRADED, "INDEXER_RECOVERING", *reasons, phase="recovering", **d)
        why = "INDEXER_RED_BEYOND_RECOVERY" if after_ready else "INDEXER_RED"
        return _input(CRITICAL, why, *reasons, phase="red", **d)
    # Serving, but the health could not be read: unmeasured, never assumed green.
    return _input(worst([state, UNKNOWN]), "INDEXER_HEALTH_UNMEASURED", *reasons, phase=phase, **d)


# --- D ---------------------------------------------------------------------------------------
def dashboard(kv):
    unit, http = kv.get("dash.unit"), kv.get("dash.http")
    if unit is None or http is None:
        return _input(UNKNOWN, "DASHBOARD_UNMEASURED")
    if unit == "active" and http in ("200", "302"):
        return _input(NOMINAL, http=http)
    # Never CRITICAL on its own: the dashboard is a viewer, the alert stream does not depend on it.
    return _input(DEGRADED, "DASHBOARD_UNAVAILABLE", http=http)


# --- F ---------------------------------------------------------------------------------------
def filebeat(kv, now):
    unit = kv.get("fb.unit")
    if unit is None:
        return _input(UNKNOWN, "FILEBEAT_UNMEASURED")
    if unit != "active":
        return _input(CRITICAL, "FILEBEAT_DOWN")
    failures = _int(kv, "fb.connect_failures_15m")
    lag = _int(kv, "fb.lag_bytes")
    reg = _int(kv, "fb.registry_mtime")
    if failures is None or lag is None or reg is None:
        return _input(UNKNOWN, "FILEBEAT_UNMEASURED", failures_15m=failures, lag_bytes=lag)
    d = {"failures_15m": failures, "lag_bytes": lag, "registry_age_s": max(0, now - reg)}
    if lag < 0:
        # The registry has no entry for the current alerts.json inode: shipping is unproven.
        return _input(UNKNOWN, "FILEBEAT_LAG_UNMEASURED", **d)
    if lag >= FILEBEAT_LAG_BYTES and d["registry_age_s"] >= FILEBEAT_NOT_SHIPPING_S:
        return _input(CRITICAL, "FILEBEAT_NOT_SHIPPING", **d)
    reasons = []
    if failures > 0:
        reasons.append("FILEBEAT_RETRYING")
    if lag >= FILEBEAT_LAG_BYTES:
        reasons.append("FILEBEAT_LAGGING")
    # Active but unable to ship is never NOMINAL.
    return _input(DEGRADED if reasons else NOMINAL, *reasons, **d)


# --- A ---------------------------------------------------------------------------------------
def agents(kv, expected):
    listed = {k.split(".")[1]: v for k, v in kv.items()
              if k.startswith("agent.") and k.endswith(".status")}
    names = {k.split(".")[1]: v for k, v in kv.items()
             if k.startswith("agent.") and k.endswith(".name")}
    if _int(kv, "agents.listed", 0) == 0 or not listed:
        return _input(UNKNOWN, "AGENTS_UNMEASURED", active={}, unexpected=[])
    exp = {e["id"]: e for e in expected}
    active = {a: st in ("Active", "Active/Local") for a, st in listed.items()}
    required = [e for e in expected if e["required"]]
    missing = [e["id"] for e in required if not active.get(e["id"])]
    unexpected = sorted(a for a in listed if a not in exp)
    mismatch = sorted(a for a in listed if a in exp and names.get(a) != exp[a]["name"])
    optional_off = [e["id"] for e in expected if not e["required"] and not active.get(e["id"])]
    reasons, state = [], NOMINAL
    if required and len(missing) * 2 >= len(required):
        reasons.append("AGENTS_MAJORITY_MISSING")
        state = CRITICAL
    elif missing:
        reasons.append("AGENT_MISSING")
        state = DEGRADED
    if unexpected:
        reasons.append("AGENT_UNEXPECTED")
        state = worst([state, DEGRADED])
    if mismatch:
        reasons.append("AGENT_IDENTITY_MISMATCH")
        state = worst([state, DEGRADED])
    if optional_off:
        reasons.append("AGENT_OPTIONAL_OFFLINE")   # informational: does not move the state
    return _input(state, *reasons, active={e["id"]: bool(active.get(e["id"])) for e in expected},
                  missing=missing, unexpected=unexpected, required_total=len(required))


# --- T ---------------------------------------------------------------------------------------
def auth(kv, expected, now):
    """Auth telemetry freshness, independent of agent keepalive (an Active agent can be blind).

    Canary hosts are judged on the newest MONITOR login (rule 5715 "Accepted publickey for monitor
    from 192.168.10.31"); hosts without that login are judged on any rule 5715 authentication
    success. Session lines, sudo and cron never count: they reach Wazuh through user journals too
    and made a blind host look fresh in July and August.
    """
    tracked = [e for e in expected if e["auth"] == "journald" and e["auth_s"] > 0]
    if kv.get("auth.scan") != "ok":
        return _input(UNKNOWN, "AUTH_UNMEASURED", last_seen={}, stale=[], tracked=len(tracked))
    last, stale = {}, []
    for e in tracked:
        key = f"auth.{e['id']}.canary" if e["canary"] else f"auth.{e['id']}.any"
        ts = _int(kv, key)
        if ts is None:
            return _input(UNKNOWN, "AUTH_UNMEASURED", last_seen={}, stale=[], tracked=len(tracked))
        last[e["id"]] = ts
        if ts <= 0 or now - ts > e["auth_s"]:
            stale.append(e["id"])
    d = {"last_seen": last, "stale": stale, "tracked": len(tracked),
         "thresholds": {e["id"]: e["auth_s"] for e in tracked}}
    if tracked and len(stale) * 2 >= len(tracked):
        return _input(CRITICAL, "AUTH_MAJORITY_STALE", **d)
    if stale:
        return _input(DEGRADED, "AUTH_STALE", **d)
    return _input(NOMINAL, **d)


# --- X ---------------------------------------------------------------------------------------
def drops(kv, prev):
    """Drops are CURRENT only if the cumulative counters grew since the previous run.

    analysisd and remoted counters are cumulative since the daemon started (measured: they reset at
    the 2026-10-03 reboot). A non-zero value therefore says drops happened at some point, not that
    they are happening. Without a previous sample: zero counters are NOMINAL, anything else is
    UNKNOWN (rate unmeasured). A counter that went DOWN is a daemon restart, never a negative delta.
    """
    dropped, received = _int(kv, "x.events_dropped"), _int(kv, "x.events_received")
    discarded = _int(kv, "x.discarded")
    if dropped is None or received is None or discarded is None:
        return _input(UNKNOWN, "DROPS_UNMEASURED", delta_dropped=None, delta_discarded=None)
    q = max(_float(kv, "x.queue_max", 0.0) or 0.0, _float(kv, "x.remoted_queue", 0.0) or 0.0)
    d = {"events_dropped": dropped, "events_received": received, "discarded": discarded,
         "queue_max": q, "delta_dropped": None, "delta_discarded": None}
    reasons, state = [], NOMINAL
    if q >= QUEUE_CRITICAL:
        reasons.append("QUEUE_SATURATED")
        state = CRITICAL
    elif q >= QUEUE_DEGRADED:
        reasons.append("QUEUE_HIGH")
        state = DEGRADED
    p = prev or {}
    pd, pr, pc = p.get("events_dropped"), p.get("events_received"), p.get("discarded")
    if pd is None or pr is None or pc is None or dropped < pd or discarded < pc or received < pr:
        # First sample, or a daemon restart reset the counters.
        if dropped == 0 and discarded == 0:
            return _input(state, *reasons, **d)
        return _input(worst([state, UNKNOWN]), "DROPS_RATE_UNMEASURED", *reasons, **d)
    d["delta_dropped"], d["delta_discarded"] = dropped - pd, discarded - pc
    lost = d["delta_dropped"] + d["delta_discarded"]
    if lost > 0:
        got = max(1, received - pr)
        sustained = (p.get("delta_lost") or 0) > 0
        if sustained or lost / got > DROP_RATIO_CRITICAL:
            reasons.append("EVENTS_DROPPED_SUSTAINED")
            state = CRITICAL
        else:
            reasons.append("EVENTS_DROPPED")
            state = worst([state, DEGRADED])
    return _input(state, *reasons, **d)


# --- aggregate -------------------------------------------------------------------------------
def unmeasured(reason="HEALTH_UNMEASURED"):
    """Every input UNKNOWN: the wrapper did not run, did not parse, or was truncated."""
    inputs = {k: _input(UNKNOWN, reason) for k in INPUTS}
    inputs["M"]["core_down"] = []
    inputs["I"]["phase"] = "unknown"
    return _finish(inputs, measured=False)


def evaluate(kv, expected, prev=None, now=None):
    """Classify one wrapper report.

    `expected` is the tracked expected-agents list (None or empty when it could not be read), and
    `prev` the previous run's drop sample (None on the first run). `now` defaults to the wrapper's
    own clock, so ages are measured on the host that produced the timestamps.
    """
    if kv.get("schema") != SCHEMA or kv.get("end") != "1":
        return unmeasured()
    if now is None:
        now = _int(kv, "now")
    if now is None:
        return unmeasured()
    if expected:
        a_in, t_in = agents(kv, expected), auth(kv, expected, now)
    else:
        # Without the tracked list nothing can say which agent is missing or which host is blind.
        a_in = _input(UNKNOWN, "EXPECTED_LIST_UNREADABLE", active={}, unexpected=[])
        t_in = _input(UNKNOWN, "EXPECTED_LIST_UNREADABLE", last_seen={}, stale=[], tracked=0)
    inputs = {
        "M": manager(kv, now),
        "I": indexer(kv, now),
        "D": dashboard(kv),
        "F": filebeat(kv, now),
        "A": a_in,
        "T": t_in,
        "X": drops(kv, prev),
    }
    return _finish(inputs, measured=True)


def _finish(inputs, measured):
    # Dependency folding: while the indexer is not NOMINAL, a dashboard 503 or Filebeat retry is a
    # SYMPTOM of it. They stay observable (their own states are kept) but are marked dependent so
    # alerting can inhibit them. Auth telemetry is never folded: it fails independently.
    idx_ok = inputs["I"]["state"] == NOMINAL
    for k in ("D", "F"):
        inputs[k]["dependent_on_indexer"] = (not idx_ok) and inputs[k]["state"] in (DEGRADED, CRITICAL)
    services = worst([inputs[k]["state"] for k in SERVICES])
    integrity = worst([inputs[k]["state"] for k in INTEGRITY])
    overall = worst([services, integrity])
    return {"schema": SCHEMA, "measured": measured, "inputs": inputs,
            "services": services, "integrity": integrity, "overall": overall,
            "services_summary": summary(inputs, SERVICES, services),
            "integrity_summary": summary(inputs, INTEGRITY, integrity),
            # Legacy fields, kept so existing consumers keep working.
            "core_down": inputs["M"].get("core_down", []),
            "up": services == NOMINAL}


def summary(inputs, keys, state):
    """A short, fixed-vocabulary label such as "CRITICAL · INDEXER_FAILED". Never free text."""
    if state == NOMINAL:
        return NOMINAL
    ranked = sorted((k for k in keys if inputs[k]["state"] != NOMINAL),
                    key=lambda k: (-SEVERITY[inputs[k]["state"]],
                                   inputs[k].get("dependent_on_indexer", False), keys.index(k)))
    words = []
    for k in ranked[:2]:
        reasons = [r for r in inputs[k]["reasons"] if r != "AGENT_OPTIONAL_OFFLINE"]
        if reasons:
            words.append(reasons[0])
    return f"{state} · {' · '.join(words)}" if words else state


def verdict(state):
    """The monitor verdict for a state. Anything unrecognised is UNKNOWN, never OK."""
    return VERDICT.get(state, "UNKNOWN")


def primary_reason(result, keys):
    """The first reason of the most severe input in `keys`, for a bounded metric label."""
    s = summary(result["inputs"], keys, worst([result["inputs"][k]["state"] for k in keys]))
    return s.split(" · ")[1] if " · " in s else ""


def drop_sample(result):
    """What the next run needs from this one to compute drop deltas."""
    x = result["inputs"]["X"]
    if x.get("events_dropped") is None:
        return None
    lost = (x.get("delta_dropped") or 0) + (x.get("delta_discarded") or 0)
    return {"events_dropped": x["events_dropped"], "events_received": x["events_received"],
            "discarded": x["discarded"], "delta_lost": lost}


# --- exports ---------------------------------------------------------------------------------
_LABEL = re.compile(r"[^A-Za-z0-9_.:/-]")


def _lbl(v):
    return _LABEL.sub("", str(v))[:48]


def prom_lines(result, expected):
    """Prometheus textfile lines. One-hot states (every state emitted, 0 or 1) so an absent series
    can be told apart from a state that is simply not current."""
    lines = []
    ins = result["inputs"]

    def head(name, kind, text):
        lines.append(f"# HELP {name} {text}")
        lines.append(f"# TYPE {name} {kind}")

    head("netframe_wazuh_health_measured", "gauge", "1 when the Wazuh health wrapper ran and parsed.")
    lines.append(f"netframe_wazuh_health_measured {1 if result['measured'] else 0}")
    head("netframe_wazuh_siem_state", "gauge", "Wazuh SIEM state per tree (one-hot).")
    for tree in ("overall", "services", "integrity"):
        for st in STATES:
            lines.append(f'netframe_wazuh_siem_state{{tree="{tree}",state="{st.lower()}"}} '
                         f"{1 if result[tree] == st else 0}")
    head("netframe_wazuh_input_state", "gauge", "Wazuh health input state (one-hot).")
    for k in INPUTS:
        for st in STATES:
            lines.append(f'netframe_wazuh_input_state{{input="{INPUT_NAME[k]}",state="{st.lower()}"}} '
                         f"{1 if ins[k]['state'] == st else 0}")
    head("netframe_wazuh_input_reason", "gauge", "Current reasons per input (fixed vocabulary).")
    for k in INPUTS:
        for r in ins[k]["reasons"]:
            lines.append(f'netframe_wazuh_input_reason{{input="{INPUT_NAME[k]}",reason="{_lbl(r)}"}} 1')
    idx = ins["I"]
    head("netframe_wazuh_indexer_phase", "gauge", "Indexer phase (one-hot).")
    for ph in ("ready", "starting", "recovering", "red", "not_serving", "failed", "down",
               "stuck_activating", "stopping", "stuck_deactivating", "unknown"):
        lines.append(f'netframe_wazuh_indexer_phase{{phase="{ph}"}} {1 if idx.get("phase") == ph else 0}')
    for name, key, text in (
            ("netframe_wazuh_indexer_restarts", "nrestarts", "systemd NRestarts of wazuh-indexer."),
            ("netframe_wazuh_indexer_start_limit_hit", "start_limit", "1 when the start limit was hit."),
            ("netframe_wazuh_indexer_activating_seconds", "activating_s", "Seconds in the current activating spell."),
            ("netframe_wazuh_indexer_red_seconds", "red_s", "Seconds the cluster has been RED."),
            ("netframe_wazuh_indexer_start_duration_seconds", "start_duration_s",
             "Start request to READY of the current indexer process.")):
        v = idx.get(key)
        if v is None:
            continue
        head(name, "gauge", text)
        lines.append(f"{name} {int(v) if not isinstance(v, bool) else int(v)}")
    a = ins["A"]
    if a.get("active"):
        head("netframe_wazuh_agent_active", "gauge", "1 when an expected agent is Active.")
        for e in expected:
            lines.append(f'netframe_wazuh_agent_active{{agent="{_lbl(e["name"])}",'
                         f'required="{"yes" if e["required"] else "no"}"}} {1 if a["active"].get(e["id"]) else 0}')
        head("netframe_wazuh_agents_unexpected", "gauge", "Registered agents not on the expected list.")
        lines.append(f"netframe_wazuh_agents_unexpected {len(a.get('unexpected', []))}")
    t = ins["T"]
    if t.get("last_seen"):
        head("netframe_wazuh_auth_last_seen_timestamp_seconds", "gauge",
             "Newest auth-telemetry proof per agent (0 = none found).")
        head("netframe_wazuh_auth_threshold_seconds", "gauge", "Auth freshness threshold per agent.")
        for e in expected:
            if e["id"] in t["last_seen"]:
                lines.append(f'netframe_wazuh_auth_last_seen_timestamp_seconds{{agent="{_lbl(e["name"])}"}} '
                             f"{t['last_seen'][e['id']]}")
                lines.append(f'netframe_wazuh_auth_threshold_seconds{{agent="{_lbl(e["name"])}"}} {e["auth_s"]}')
    x = ins["X"]
    if x.get("events_dropped") is not None:
        for name, key, kind in (("netframe_wazuh_events_received_total", "events_received", "counter"),
                                ("netframe_wazuh_events_dropped_total", "events_dropped", "counter"),
                                ("netframe_wazuh_remoted_discarded_total", "discarded", "counter")):
            head(name, kind, f"Wazuh {key} (cumulative since the daemon started).")
            lines.append(f"{name} {x[key]}")
        head("netframe_wazuh_queue_usage_ratio", "gauge", "Highest analysisd or remoted queue usage.")
        lines.append(f"netframe_wazuh_queue_usage_ratio {x['queue_max']:.2f}")
    f = ins["F"]
    for name, key in (("netframe_wazuh_filebeat_connect_failures_15m", "failures_15m"),
                      ("netframe_wazuh_filebeat_lag_bytes", "lag_bytes")):
        if f.get(key) is not None:
            head(name, "gauge", f"Filebeat {key}.")
            lines.append(f"{name} {f[key]}")
    m = ins["M"]
    if m.get("alerts_mtime"):
        head("netframe_wazuh_alerts_last_written_timestamp_seconds", "gauge",
             "Modification time of the manager's alerts.json.")
        lines.append(f"netframe_wazuh_alerts_last_written_timestamp_seconds {m['alerts_mtime']}")
    return lines


def flat(result, prefix):
    """Compact numeric view for history.jsonl. Only measured values are written."""
    out = {f"{prefix}.services": SEVERITY[result["services"]],
           f"{prefix}.integrity": SEVERITY[result["integrity"]]}
    for k in INPUTS:
        out[f"{prefix}.{INPUT_NAME[k]}"] = SEVERITY[result["inputs"][k]["state"]]
    sample = drop_sample(result)
    if sample:
        for key, v in sample.items():
            out[f"{prefix}.x_{key}"] = v
    idx = result["inputs"]["I"]
    if idx.get("start_duration_s") is not None:
        out[f"{prefix}.indexer_start_duration_s"] = idx["start_duration_s"]
    return out


def prev_from_flat(flat_metrics, prefix):
    """Recover the previous run's drop sample from a history record's flat metrics."""
    if not isinstance(flat_metrics, dict):
        return None
    keys = ("events_dropped", "events_received", "discarded", "delta_lost")
    vals = {k: flat_metrics.get(f"{prefix}.x_{k}") for k in keys}
    if any(vals[k] is None for k in keys[:3]):
        return None
    return vals
