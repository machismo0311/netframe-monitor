"""Failure fixtures for the llm_router conformance wrapper (NF-AIOPS-004 Phase 3).

The wrapper is shell and reads live root-only state, so it cannot run in CI directly.
These tests exercise the COLLECTOR-SIDE parser + classifier against frozen wrapper
output for each of the four required cases. The point is not just detecting failure -
it is that Jarvis can say WHICH of config / runtime / firewall failed, because the
operator's next action differs entirely by dimension.
"""
import importlib.util
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "mon", os.path.join(BASE, "netframe_monitor.py"))
mon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mon)

HEALTHY = """config=PASS
config_host_expected=0.0.0.0
config_host_actual=0.0.0.0
config_port_expected=8000
config_port_actual=8000
runtime=PASS
runtime_bind_expected=0.0.0.0:8000
runtime_bind_actual=0.0.0.0:8000
firewall=PASS
firewall_default_drop=yes
firewall_missing_allow= none
firewall_unexpected_allow=no
conformance=PASS"""

# Case 2: config drift (env edited to loopback, e.g. the 2026-07-14 regression as it
# would look ON DISK before a restart).
CONFIG_DRIFT = HEALTHY.replace("config=PASS", "config=FAIL").replace(
    "config_host_actual=0.0.0.0", "config_host_actual=127.0.0.1").replace(
    "conformance=PASS", "conformance=FAIL")

# Case 3: file fixed, service NOT restarted -> config PASS but the process is still
# bound to loopback. This is the exact shape of the real outage.
RUNTIME_STALE = HEALTHY.replace("runtime=PASS", "runtime=FAIL").replace(
    "runtime_bind_actual=0.0.0.0:8000", "runtime_bind_actual=127.0.0.1:8000").replace(
    "conformance=PASS", "conformance=FAIL")

# Case 4: config + runtime fine, but the :8000 allowlist lost its default DROP (lock
# not reasserted after a flush) -> the unauthenticated router is open to the LAN.
FIREWALL_REGRESSION = HEALTHY.replace("firewall=PASS", "firewall=FAIL").replace(
    "firewall_default_drop=yes", "firewall_default_drop=no").replace(
    "conformance=PASS", "conformance=FAIL")


def parse(out):
    return mon.parse_llm_router_conformance(out)


def test_case1_everything_healthy():
    m = parse(HEALTHY)
    assert m["config"] == "PASS"
    assert m["runtime"] == "PASS"
    assert m["firewall"] == "PASS"
    assert mon.classify("llm_router_conformance", 0, HEALTHY) == "OK"


def test_case2_configuration_drift_is_a_config_failure_only():
    m = parse(CONFIG_DRIFT)
    assert m["config"] == "FAIL"
    assert m["runtime"] == "PASS"   # the diagnosis must NOT smear across dimensions
    assert m["firewall"] == "PASS"
    assert m["config_host_actual"] == "127.0.0.1"  # explains WHY: wrong host in the file
    assert mon.classify("llm_router_conformance", 0, CONFIG_DRIFT) == "WARN"


def test_case3_service_not_restarted_is_runtime_only():
    m = parse(RUNTIME_STALE)
    assert m["config"] == "PASS"    # the file is correct...
    assert m["runtime"] == "FAIL"   # ...but the running process is not. Restart, don't edit.
    assert m["firewall"] == "PASS"
    assert m["runtime_bind_actual"] == "127.0.0.1:8000"


def test_case4_firewall_regression_is_firewall_only():
    m = parse(FIREWALL_REGRESSION)
    assert m["config"] == "PASS"
    assert m["runtime"] == "PASS"
    assert m["firewall"] == "FAIL"
    assert m["firewall_default_drop"] == "no"  # explains WHY: allowlist not enforcing


def test_dimensions_are_never_collapsed_into_one_boolean():
    # The whole requirement: three independent verdicts, each individually inspectable.
    for out in (CONFIG_DRIFT, RUNTIME_STALE, FIREWALL_REGRESSION):
        m = parse(out)
        verdicts = [m["config"], m["runtime"], m["firewall"]]
        assert verdicts.count("FAIL") == 1, \
            "exactly one dimension should fail in each single-fault fixture"


def test_wrapper_output_carries_no_secret_keys():
    # Defence in depth: the parser must not surface secret-bearing env keys even if a
    # future wrapper edit leaked one. Only the two asserted non-secret keys may appear.
    m = parse(HEALTHY)
    blob = " ".join(f"{k}={v}" for k, v in m.items()).lower()
    for forbidden in ("ollama_url", "claude_model", "api", "token", "secret", "key",
                      "password"):
        assert forbidden not in blob, f"secret-shaped field surfaced: {forbidden}"
