#!/usr/bin/env python3
"""Admission control for resource-consuming probes (NF-AIOPS-004, Phase 2).

The monitoring system must never become the workload it monitors. The 72B occupies
roughly 47 GB of 48 GB VRAM, so any deep inference is effectively a global lock on
inference for its duration. Transact probes therefore run only when the GPU is genuinely
idle, and when they cannot run they report SKIPPED.

SKIPPED is not a failure and not health. It means "insufficient test conditions". It must
never degrade the overall verdict, and it must never be reported as WARN or FAIL: a
service whose functional test could not run is a service we simply did not test, and
saying anything stronger would be a lie in either direction.

Policy - ALL of these must hold for a probe to be admitted:

    no 72B resident in Ollama           else -> "Inference workload active"
    GPU utilisation below threshold     else -> "GPU busy"
    no recent interactive user request  else -> "Interactive user request"
    not inside a maintenance window     else -> "Maintenance window"
    minimum interval since last attempt else -> "Not due"

Interactive work always wins. This module never waits, queues, or preempts; it defers.

CLI:
  netframe_admission.py check console     # would a console transact probe be admitted?
  netframe_admission.py state             # dump the raw signals
"""
import json
import os
import re
import subprocess
import sys
import time

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
STAMPS = f"{BASE}/context/transact-stamps.json"
MAINT_FLAG = f"{BASE}/context/maintenance-window"
CONVERSATIONS = f"{BASE}/context/conversations.jsonl"

# A 72B pass is a global inference lock, so treat its residency as an absolute veto.
DEEP_MODEL_RE = re.compile(r"72b", re.IGNORECASE)
# Below this the GPU is idle enough that a 7B probe will not be felt by a live user.
GPU_BUSY_PCT = int(os.environ.get("NETFRAME_GPU_BUSY_PCT", "25"))
# Any interactive request inside this window defers the probe.
INTERACTIVE_WINDOW_S = int(os.environ.get("NETFRAME_INTERACTIVE_WINDOW_S", "300"))
# Transact probes are hourly at most; the collector itself runs every 15 minutes.
MIN_INTERVAL_S = int(os.environ.get("NETFRAME_TRANSACT_INTERVAL_S", "3600"))
TIMEOUT = 8


def _run(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    return p.stdout if p.returncode == 0 else None


def gpu_state():
    """[(util_pct, mem_used_mib), ...] per GPU, or [] if nvidia-smi is unavailable."""
    out = _run(["nvidia-smi", "--query-gpu=utilization.gpu,memory.used",
                "--format=csv,noheader,nounits"])
    if not out:
        return []
    state = []
    for line in out.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            state.append((int(parts[0]), int(parts[1])))
    return state


def resident_models():
    """Model names currently resident in Ollama (`ollama ps`), or [] if unknown."""
    out = _run(["ollama", "ps"])
    if not out:
        return []
    lines = out.strip().splitlines()[1:]  # drop header
    return [ln.split()[0] for ln in lines if ln.split()]


def deep_model_resident():
    return any(DEEP_MODEL_RE.search(m) for m in resident_models())


def gpu_busy():
    state = gpu_state()
    if not state:
        # No GPU visibility is not permission. Fail closed: if we cannot prove the GPU is
        # idle, we do not spend it. A skipped probe is cheap; a stolen GPU is not.
        return True, "GPU state unknown"
    worst = max(u for u, _ in state)
    return worst > GPU_BUSY_PCT, f"GPU utilisation {worst}% (threshold {GPU_BUSY_PCT}%)"


def interactive_recent():
    """True if a human asked the console or Open WebUI something recently.

    Two independent signals, because they use different paths: the console logs every
    exchange to conversations.jsonl, while Open WebUI traffic only ever appears in
    llm_router's journal. Either one means a person is using the system right now.
    """
    now = time.time()
    if os.path.exists(CONVERSATIONS):
        try:
            if now - os.path.getmtime(CONVERSATIONS) < INTERACTIVE_WINDOW_S:
                return True, "recent console conversation"
        except OSError:
            pass
    out = _run(["journalctl", "-u", "llm_router.service", "-q", "--no-pager",
                "--since", f"-{INTERACTIVE_WINDOW_S} seconds"])
    if out and "chat/completions" in out:
        return True, "recent Open WebUI request via llm_router"
    return False, ""


def maintenance_window():
    return os.path.exists(MAINT_FLAG)


def _stamps():
    if os.path.exists(STAMPS):
        try:
            with open(STAMPS) as fh:
                return json.load(fh)
        except (ValueError, OSError):
            return {}
    return {}


def record_attempt(probe):
    s = _stamps()
    s[probe] = time.time()
    os.makedirs(os.path.dirname(STAMPS), exist_ok=True)
    tmp = f"{STAMPS}.tmp"
    with open(tmp, "w") as fh:
        json.dump(s, fh, indent=2)
    os.replace(tmp, STAMPS)


def due(probe):
    last = _stamps().get(probe)
    if last is None:
        return True, ""
    age = time.time() - last
    if age >= MIN_INTERVAL_S:
        return True, ""
    return False, f"Not due ({int(MIN_INTERVAL_S - age)}s remaining of {MIN_INTERVAL_S}s)"


def decide(probe):
    """-> {"attempted": bool, "reason": str}. Reason is "" when admitted.

    Order matters only for which reason gets reported; any single veto is sufficient.
    Cheap, local checks first.
    """
    if maintenance_window():
        return {"attempted": False, "reason": "Maintenance window"}
    ok, detail = due(probe)
    if not ok:
        return {"attempted": False, "reason": detail}
    if deep_model_resident():
        return {"attempted": False, "reason": "Inference workload active (72B resident)"}
    busy, detail = gpu_busy()
    if busy:
        return {"attempted": False, "reason": f"GPU busy ({detail})"}
    active, detail = interactive_recent()
    if active:
        return {"attempted": False, "reason": f"Interactive user request ({detail})"}
    return {"attempted": True, "reason": ""}


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "check":
        d = decide(sys.argv[2])
        print(f"attempted={'YES' if d['attempted'] else 'NO'} reason={d['reason'] or '-'}")
    elif len(sys.argv) > 1 and sys.argv[1] == "state":
        print(json.dumps({
            "gpu": gpu_state(),
            "resident_models": resident_models(),
            "deep_resident": deep_model_resident(),
            "gpu_busy": gpu_busy(),
            "interactive_recent": interactive_recent(),
            "maintenance_window": maintenance_window(),
            "stamps": _stamps(),
        }, indent=2))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
