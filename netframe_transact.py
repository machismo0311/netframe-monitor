#!/usr/bin/env python3
"""Transact probes: prove the user journey actually works (NF-AIOPS-004, Phase 2).

The tier above reachability and authentication. Reachability proves the path exists;
authentication proves the gate is correct; a transact probe performs one real, read-only
user action and asserts the response is genuinely usable.

Why this tier is not optional: NPM evaluates auth_basic in nginx's access phase, BEFORE
proxy_pass in the content phase. An un-credentialed request therefore returns 401 without
the upstream ever being contacted, so console_auth/page_auth report 401 = healthy even if
the backend is completely dead. They prove the gate, not the service.

Constraints (NF-AIOPS-004, owner-approved):
  - NEVER the 72B. A deep pass is a global inference lock; monitoring must not take it.
    Enforced twice here: refuse to send a deep model, and reject the response if one
    answered anyway.
  - Hourly at most, and only when admission control says the GPU is genuinely free.
  - Cannot run -> SKIPPED. Never WARN, never FAIL. A skipped probe is an untested
    service, which is different from a healthy one AND from a broken one.

Output is one key=value line, parsed by the collector:
  probe=console attempted=YES result=PASS http=200 model=qwen2.5:7b elapsed_s=13
  probe=console attempted=NO reason=GPU busy (GPU utilisation 96% ...)

CLI:
  netframe_transact.py console      # run (or skip) the console transact probe
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netframe_admission  # noqa: E402

CONSOLE_URL = os.environ.get("NETFRAME_CONSOLE_URL", "http://127.0.0.1:8809")
# Mirrors netframe_chat's fast tier. If these ever diverge, the response-side guard below
# still refuses anything that looks deep.
FAST_MODEL = os.environ.get("NETFRAME_CHAT_MODEL", "qwen2.5:7b")
DEEP_RE = re.compile(r"72b", re.IGNORECASE)
TIMEOUT = 60
QUESTION = "Reply in one short sentence: is the cluster healthy?"


def _emit(**kv):
    print(" ".join(f"{k}={v}" for k, v in kv.items()))


def probe_console():
    """One real read-only console exchange, on the fast model only."""
    # Guard 1: refuse before spending anything if the fast tier is misconfigured deep.
    if DEEP_RE.search(FAST_MODEL):
        return {"attempted": "NO",
                "reason": f"refusing: fast model is configured deep ({FAST_MODEL})"}

    payload = json.dumps({"question": QUESTION, "mode": "operator", "deep": False}).encode()
    req = urllib.request.Request(f"{CONSOLE_URL}/api/chat", data=payload,
                                 headers={"Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            code = resp.getcode()
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"attempted": "YES", "result": "FAIL", "http": e.code,
                "elapsed_s": int(time.time() - t0)}
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as e:
        return {"attempted": "YES", "result": "FAIL", "http": "000",
                "error": type(e).__name__, "elapsed_s": int(time.time() - t0)}
    elapsed = int(time.time() - t0)

    model = str(body.get("model", "?"))
    # Guard 2: something answered on the deep model. Report it rather than let a silent
    # policy breach look like a healthy probe.
    if DEEP_RE.search(model):
        return {"attempted": "YES", "result": "FAIL", "http": code, "model": model,
                "error": "deep-model-answered-policy-breach", "elapsed_s": elapsed}
    # A 200 carrying no usable answer is not a working service.
    if code != 200 or not str(body.get("response", "")).strip():
        return {"attempted": "YES", "result": "FAIL", "http": code, "model": model,
                "error": "empty-response", "elapsed_s": elapsed}
    return {"attempted": "YES", "result": "PASS", "http": code, "model": model,
            "sources": len(body.get("sources") or []), "elapsed_s": elapsed}


PROBES = {"console": probe_console}


def run(name):
    if name not in PROBES:
        _emit(probe=name, attempted="NO", reason=f"unknown probe '{name}'")
        return
    decision = netframe_admission.decide(name)
    if not decision["attempted"]:
        _emit(probe=name, attempted="NO", reason=decision["reason"])
        return
    # Stamp before running: a probe that hangs or crashes must still consume its hourly
    # slot, or a failing probe would retry every 15 minutes and become the workload.
    netframe_admission.record_attempt(name)
    _emit(probe=name, **PROBES[name]())


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    run(sys.argv[1])


if __name__ == "__main__":
    main()
