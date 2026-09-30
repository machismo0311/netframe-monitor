"""Fixtures for the dual-WAN failover posture check (pve2 -> OPNsense VM 100).

The wrapper runs `qm guest exec` as root and reads live pf state, so it cannot run in CI.
These tests exercise the COLLECTOR-SIDE parser and classifier against frozen wrapper output.

What is actually being defended. This check feeds a wall display whose green state asserts
"a WAN1 failure is survivable". Between 2026-08-15 and 2026-09-09 the FirstNet standby was
dead for 25 days while the wall stayed green, because one fact (WAN2 health) was absent and
absence rendered as health. So the invariant under test is not "does it parse" - it is that
every unobserved fact stays UNKNOWN and never resolves to a reassuring value.

`armed` is tri-state deliberately: True / False / None are three different operational
situations - protected, knowingly unprotected, and not observed - and a boolean cannot hold
the third without lying about one of the other two.
"""
import importlib.util
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "mon", os.path.join(BASE, "netframe_monitor.py"))
mon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mon)

# The live healthy baseline, as emitted by the wrapper on pve2 on 2026-09-10.
ARMED_WAN1 = """source_ok=true
armed=true
groups_total=1
group=Failover
tiers=2
active_netif=vtnet0
active_path=wan1"""

ARMED_WAN2 = ARMED_WAN1.replace("active_netif=vtnet0", "active_netif=vtnet2").replace(
    "active_path=wan1", "active_path=wan2")

# A gateway group exists, but no enabled rule routes through it. The wrapper resolves the
# conjunction itself, so it reports armed=false and names no group.
GROUP_UNUSED = """source_ok=true
armed=false
groups_total=1
active_netif=vtnet0
active_path=wan1"""

# Only rule referencing the group is disabled - indistinguishable from unused, by design.
RULE_DISABLED = GROUP_UNUSED

# Group dropped to a single tier (config drift). No >=2-tier group, so nothing is armed.
SINGLE_TIER = GROUP_UNUSED

SOURCE_FAIL = """source_ok=false
reason=EXEC_FAILED"""

# pf returned no policy route-to for local nets: armed is known, the live path is not.
PATH_UNKNOWN = """source_ok=true
armed=true
groups_total=1
group=Failover
tiers=2
active_path=unknown"""


def v(out):
    return mon.classify("wan_failover", 0, out)


# ---- M1: armed, primary active -> the only OK state -------------------------------
def test_m1_armed_wan1_active():
    d = mon.parse_wan_posture(ARMED_WAN1)
    assert d["armed"] is True
    assert d["active_path"] == "wan1"
    assert d["group"] == "Failover"
    assert d["tiers"] == 2
    assert d["source_ok"] is True


# ---- M2: armed, standby carrying traffic ------------------------------------------
def test_m2_armed_wan2_active():
    d = mon.parse_wan_posture(ARMED_WAN2)
    assert d["armed"] is True
    assert d["active_path"] == "wan2"


# ---- M3: group exists but nothing routes through it -------------------------------
def test_m3_group_exists_unused():
    d = mon.parse_wan_posture(GROUP_UNUSED)
    assert d["armed"] is False
    assert d["group"] is None, "an unarmed posture must not name a group as if it were in force"


# ---- M4: the only referencing rule is disabled ------------------------------------
def test_m4_rule_disabled():
    assert mon.parse_wan_posture(RULE_DISABLED)["armed"] is False


# ---- M5: single-tier drift --------------------------------------------------------
def test_m5_single_tier():
    assert mon.parse_wan_posture(SINGLE_TIER)["armed"] is False


# ---- M6: authoritative source failure ---------------------------------------------
def test_m6_source_failure_is_unknown_not_false():
    d = mon.parse_wan_posture(SOURCE_FAIL)
    assert d["source_ok"] is False
    assert d["armed"] is None, "a failed read states NOTHING about arming; None, never False"
    assert d["active_path"] is None
    assert d["reason"] == "EXEC_FAILED"


def test_m6b_empty_output_is_unknown():
    d = mon.parse_wan_posture("")
    assert d["source_ok"] is None
    assert d["armed"] is None
    assert d["active_path"] is None


# ---- active path is never guessed -------------------------------------------------
def test_path_unknown_stays_unknown():
    d = mon.parse_wan_posture(PATH_UNKNOWN)
    assert d["armed"] is True
    assert d["active_path"] is None, "'unknown' must not collapse to the primary"


def test_unrecognised_netif_is_unknown():
    d = mon.parse_wan_posture(ARMED_WAN1.replace("active_path=wan1", "active_path=vtnet9"))
    assert d["active_path"] is None


# ---- verdicts ---------------------------------------------------------------------
def test_verdict_ok_only_when_armed_and_on_primary():
    assert v(ARMED_WAN1) == "OK"


def test_verdict_warn_when_running_on_standby():
    assert v(ARMED_WAN2) == "WARN", "already on LTE with no further fallback is not OK"


def test_verdict_warn_when_not_armed():
    assert v(GROUP_UNUSED) == "WARN"


def test_verdict_warn_when_source_unreadable():
    assert v(SOURCE_FAIL) == "WARN", "not seeing the safety net is not the same as having one"


def test_verdict_warn_when_path_unproven():
    assert v(PATH_UNKNOWN) == "WARN"


def test_no_state_is_ok_except_the_protected_one():
    outs = [ARMED_WAN1, ARMED_WAN2, GROUP_UNUSED, SOURCE_FAIL, PATH_UNKNOWN, ""]
    assert [v(o) for o in outs].count("OK") == 1


# ---- the output vocabulary stays bounded ------------------------------------------
def test_parser_never_emits_freeform_text():
    d = mon.parse_wan_posture("source_ok=false\nreason=EXEC_FAILED\nstray=rm -rf /\n")
    assert set(d) == {"source_ok", "armed", "group", "tiers",
                      "active_path", "active_netif", "reason"}
    assert d["reason"] == "EXEC_FAILED"


if __name__ == "__main__":
    import sys
    fails = []
    for n, f in sorted(globals().items()):
        if n.startswith("test_") and callable(f):
            try:
                f()
                print("PASS ", n)
            except AssertionError as e:
                print("FAIL ", n, e)
                fails.append(n)
            except Exception as e:
                # Reported, not swallowed: a non-assertion failure must not abort the
                # rest. `Exception` deliberately does not catch KeyboardInterrupt or
                # SystemExit, which still propagate.
                print("FAIL ", n, f"{type(e).__name__}: {e}")
                fails.append(n)
    print("----")
    print("WAN POSTURE PRODUCER: " + ("FAIL " + str(fails) if fails else "PASS"))
    sys.exit(1 if fails else 0)
