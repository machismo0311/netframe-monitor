"""Packet C: truthful Wazuh SIEM health. Classifier, wrapper and monitor integration.

These assert that the wall can no longer read Wazuh as healthy when it is not: indexer down,
dashboard unavailable, Filebeat unable to ship, an expected agent missing, auth telemetry stale
(including while every agent is Active), or the manager dropping events. And that the transient
states A3 measured (a 242 s cold start, 11 min 25 s of RED shard recovery) are not reported as
outages. UNKNOWN is checked to be fail-visible everywhere.

Run: python3 -m pytest tests/test_wazuh_health.py -q
"""
import gzip
import importlib.machinery
import importlib.util
import json
import os
import re
import types
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(mod):
    spec = importlib.util.spec_from_file_location(mod, os.path.join(BASE, f"{mod}.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


WH = _load("netframe_wazuh_health")
mon = _load("netframe_monitor")
EXPECTED = WH.load_expected(os.path.join(BASE, "wazuh-expected-agents.psv"))
NOW = 1_790_000_000
IDS = [e["id"] for e in EXPECTED]
BY_NAME = {e["name"]: e["id"] for e in EXPECTED}


def healthy(**over):
    """A report in which all seven inputs are nominal. Keyword overrides use '__' for '.'."""
    kv = {"schema": WH.SCHEMA, "now": str(NOW), "end": "1",
          "mgr.unit": "active", "mgr.daemon.maild": "stopped", "mgr.api_http": "401",
          "mgr.alerts_mtime": str(NOW - 30), "mgr.alerts_size": "1000",
          "x.events_received": "5000", "x.events_dropped": "0", "x.discarded": "0",
          "x.queue_max": "0.00", "x.remoted_queue": "0.00",
          "idx.unit": "active", "idx.sub": "running", "idx.result": "success",
          "idx.nrestarts": "0", "idx.timeout_start_s": "420",
          "idx.exec_start": str(NOW - 86400 - 242), "idx.active_enter": str(NOW - 86400),
          "idx.state_change": str(NOW - 86400), "idx.boot_timeouts": "0",
          "idx.boot_sched_restarts": "0", "idx.boot_start_limit": "0",
          "idx.http": "401", "idx.health": "green",
          "idx.health_change_at": str(NOW - 86400 + 685), "idx.health_change_to": "green",
          "dash.unit": "active", "dash.http": "302",
          "fb.unit": "active", "fb.connect_failures_15m": "0", "fb.registry_mtime": str(NOW - 5),
          "fb.lag_bytes": "0", "agents.listed": str(len(EXPECTED)), "auth.scan": "ok"}
    for d in WH.MANAGER_TIER1 + WH.MANAGER_TIER2:
        kv[f"mgr.daemon.{d}"] = "running"
    for e in EXPECTED:
        kv[f"agent.{e['id']}.name"] = e["name"]
        kv[f"agent.{e['id']}.status"] = "Active/Local" if e["id"] == "000" else "Active"
        kv[f"auth.{e['id']}.any"] = str(NOW - 600)
        kv[f"auth.{e['id']}.canary"] = str(NOW - 600) if e["canary"] else "0"
    for k, v in over.items():
        key = k.replace("__", ".")
        if v is None:
            kv.pop(key, None)
        else:
            kv[key] = str(v)
    return kv


def ev(kv, prev=None, expected=EXPECTED):
    return WH.evaluate(kv, expected, prev=prev)


def state(res, k):
    return res["inputs"][k]["state"]


def reasons(res, k):
    return res["inputs"][k]["reasons"]


def broken_2026_10_02():
    """The state measured on 2026-10-02 at about 16:30Z, before A1: indexer failed on a start
    timeout since 09-27, dashboard 503, Filebeat in a reconnect loop behind the indexer, 10/10
    agents Active, auth fresh only on pve1, no drops."""
    kv = healthy(idx__unit="failed", idx__sub="failed", idx__result="timeout",
                 idx__active_enter=0, idx__http="000", idx__health="unknown",
                 idx__boot_timeouts=1, dash__http="503", fb__connect_failures_15m=19,
                 fb__lag_bytes=24_000_000, fb__registry_mtime=NOW - 5 * 86400)
    for e in EXPECTED:
        if e["name"] != "pve1" and e["auth"] == "journald":
            kv[f"auth.{e['id']}.any"] = str(NOW - 5 * 86400)
            kv[f"auth.{e['id']}.canary"] = str(NOW - 5 * 86400) if e["canary"] else "0"
    return kv


# 1 and 19 ---------------------------------------------------------------------------------------
def test_healthy_fixture_is_nominal():
    res = ev(healthy())
    assert res["overall"] == res["services"] == res["integrity"] == "NOMINAL"
    assert WH.verdict(res["services"]) == "OK" and WH.verdict(res["integrity"]) == "OK"


def test_all_seven_inputs_are_measured_and_nominal():
    res = ev(healthy())
    assert set(res["inputs"]) == set(WH.INPUTS)
    assert all(state(res, k) == "NOMINAL" for k in WH.INPUTS), {k: state(res, k) for k in WH.INPUTS}
    assert res["measured"] is True


# 2 and 3 ----------------------------------------------------------------------------------------
def test_indexer_failed_is_critical():
    res = ev(healthy(idx__unit="failed", idx__result="timeout", idx__http="000"))
    assert state(res, "I") == "CRITICAL"
    assert "INDEXER_FAILED" in reasons(res, "I") and "INDEXER_START_TIMEOUT" in reasons(res, "I")
    assert res["services"] == "CRITICAL" and WH.verdict(res["services"]) == "CRIT"


def test_healthy_manager_never_hides_a_failed_indexer():
    res = ev(healthy(idx__unit="failed", idx__result="timeout", idx__http="000"))
    assert state(res, "M") == "NOMINAL"
    assert res["overall"] != "NOMINAL" and res["up"] is False


def test_indexer_down_is_critical():
    res = ev(healthy(idx__unit="inactive", idx__http="000"))
    assert state(res, "I") == "CRITICAL" and "INDEXER_DOWN" in reasons(res, "I")


# 4: A3-aware starting -----------------------------------------------------------------------------
def test_indexer_starting_within_budget_is_degraded_not_critical():
    res = ev(healthy(idx__unit="activating", idx__state_change=NOW - 120, idx__exec_start=NOW - 120,
                     idx__http="000", idx__health="unknown"))
    assert state(res, "I") == "DEGRADED"
    assert res["inputs"]["I"]["phase"] == "starting" and "INDEXER_STARTING" in reasons(res, "I")


def test_measured_242s_cold_start_still_starting_is_not_critical():
    res = ev(healthy(idx__unit="activating", idx__state_change=NOW - 242, idx__exec_start=NOW - 242))
    assert state(res, "I") == "DEGRADED"


def test_indexer_activating_beyond_both_attempts_is_stuck():
    res = ev(healthy(idx__unit="activating", idx__state_change=NOW - 901, idx__exec_start=NOW - 901))
    assert state(res, "I") == "CRITICAL" and "INDEXER_STUCK_ACTIVATING" in reasons(res, "I")
    edge = ev(healthy(idx__unit="activating", idx__state_change=NOW - 900, idx__exec_start=NOW - 900))
    assert state(edge, "I") == "DEGRADED"


def test_indexer_retry_in_progress_is_reported():
    res = ev(healthy(idx__unit="activating", idx__state_change=NOW - 60, idx__nrestarts=1,
                     idx__boot_timeouts=1, idx__boot_sched_restarts=1))
    assert state(res, "I") == "DEGRADED" and "INDEXER_START_RETRIED" in reasons(res, "I")


def test_stuck_stop_is_critical():
    res = ev(healthy(idx__unit="deactivating", idx__state_change=NOW - 601))
    assert state(res, "I") == "CRITICAL" and "INDEXER_STUCK_DEACTIVATING" in reasons(res, "I")
    ok = ev(healthy(idx__unit="deactivating", idx__state_change=NOW - 26))
    assert state(ok, "I") == "DEGRADED" and "INDEXER_STOPPING" in reasons(ok, "I")


# 5 and 6: RED after READY -------------------------------------------------------------------------
def test_red_four_minutes_after_ready_is_recovering_not_critical():
    res = ev(healthy(idx__active_enter=NOW - 240, idx__state_change=NOW - 240,
                     idx__exec_start=NOW - 482, idx__health="red",
                     idx__health_change_at=NOW - 90000, idx__health_change_to="green"))
    assert state(res, "I") == "DEGRADED"
    assert res["inputs"]["I"]["phase"] == "recovering" and "INDEXER_RECOVERING" in reasons(res, "I")
    assert res["inputs"]["I"]["red_s"] == 240


def test_measured_11m25s_recovery_stays_inside_the_allowance():
    res = ev(healthy(idx__active_enter=NOW - 685, idx__exec_start=NOW - 927, idx__health="red"))
    assert state(res, "I") == "DEGRADED"


def test_red_beyond_fifteen_minutes_after_ready_is_critical():
    res = ev(healthy(idx__active_enter=NOW - 901, idx__exec_start=NOW - 1143, idx__health="red"))
    assert state(res, "I") == "CRITICAL" and "INDEXER_RED_BEYOND_RECOVERY" in reasons(res, "I")
    edge = ev(healthy(idx__active_enter=NOW - 900, idx__exec_start=NOW - 1142, idx__health="red"))
    assert state(edge, "I") == "DEGRADED"


def test_red_long_after_ready_gets_no_recovery_allowance():
    res = ev(healthy(idx__health="red", idx__health_change_at=NOW - 60, idx__health_change_to="red"))
    assert state(res, "I") == "CRITICAL" and "INDEXER_RED" in reasons(res, "I")


def test_503_right_after_ready_is_recovering_but_later_is_not_serving():
    early = ev(healthy(idx__active_enter=NOW - 11, idx__exec_start=NOW - 253, idx__http="503",
                       idx__health="unknown"))
    assert state(early, "I") == "DEGRADED" and "INDEXER_RECOVERING" in reasons(early, "I")
    late = ev(healthy(idx__http="503", idx__health="unknown"))
    assert state(late, "I") == "CRITICAL" and "INDEXER_NOT_SERVING" in reasons(late, "I")


def test_yellow_is_degraded():
    res = ev(healthy(idx__health="yellow"))
    assert state(res, "I") == "DEGRADED" and "INDEXER_YELLOW" in reasons(res, "I")


def test_unreadable_cluster_health_is_unknown_never_green():
    res = ev(healthy(idx__health="unknown"))
    assert state(res, "I") == "UNKNOWN" and res["services"] == "UNKNOWN"
    assert WH.verdict(res["services"]) != "OK"


# 7: slow start --------------------------------------------------------------------------------
def test_start_over_300s_is_a_slow_start_warning():
    res = ev(healthy(idx__exec_start=NOW - 86400 - 301))
    assert state(res, "I") == "DEGRADED" and "INDEXER_SLOW_START" in reasons(res, "I")
    assert res["inputs"]["I"]["start_duration_s"] == 301


def test_measured_242s_start_and_the_300s_edge_are_nominal():
    assert state(ev(healthy()), "I") == "NOMINAL"
    assert state(ev(healthy(idx__exec_start=NOW - 86400 - 300)), "I") == "NOMINAL"


def test_completed_retry_keeps_the_indexer_degraded():
    res = ev(healthy(idx__nrestarts=1))
    assert state(res, "I") == "DEGRADED" and "INDEXER_START_RETRIED" in reasons(res, "I")


# 8: start limit --------------------------------------------------------------------------------
def test_start_limit_hit_is_critical():
    for over in ({"idx__result": "start-limit-hit"},
                 {"idx__result": "timeout", "idx__boot_start_limit": 1}):
        res = ev(healthy(idx__unit="failed", idx__http="000", **over))
        assert state(res, "I") == "CRITICAL" and "INDEXER_START_LIMIT" in reasons(res, "I"), over


# 9: Filebeat ----------------------------------------------------------------------------------
def test_filebeat_active_but_reconnecting_is_not_nominal():
    res = ev(healthy(fb__connect_failures_15m=12))
    assert state(res, "F") == "DEGRADED" and "FILEBEAT_RETRYING" in reasons(res, "F")


def test_filebeat_lagging_and_not_shipping():
    lag = ev(healthy(fb__lag_bytes=5_000_000))
    assert state(lag, "F") == "DEGRADED" and "FILEBEAT_LAGGING" in reasons(lag, "F")
    stuck = ev(healthy(fb__lag_bytes=5_000_000, fb__registry_mtime=NOW - 25 * 3600))
    assert state(stuck, "F") == "CRITICAL" and "FILEBEAT_NOT_SHIPPING" in reasons(stuck, "F")


def test_filebeat_down_or_unmeasured():
    assert state(ev(healthy(fb__unit="failed")), "F") == "CRITICAL"
    assert state(ev(healthy(fb__lag_bytes=-1)), "F") == "UNKNOWN"
    assert state(ev(healthy(fb__lag_bytes=None)), "F") == "UNKNOWN"


# D ------------------------------------------------------------------------------------------
def test_dashboard_503_is_degraded_and_never_critical_alone():
    res = ev(healthy(dash__http="503"))
    assert state(res, "D") == "DEGRADED" and res["services"] == "DEGRADED"
    assert state(ev(healthy(dash__unit="failed", dash__http="000")), "D") == "DEGRADED"
    assert state(ev(healthy(dash__http="200")), "D") == "NOMINAL"
    assert state(ev(healthy(dash__http=None)), "D") == "UNKNOWN"


def test_indexer_outage_folds_dashboard_and_filebeat_but_keeps_them_visible():
    res = ev(healthy(idx__unit="failed", idx__http="000", dash__http="503", fb__connect_failures_15m=19))
    assert state(res, "D") == "DEGRADED" and state(res, "F") == "DEGRADED"
    assert res["inputs"]["D"]["dependent_on_indexer"] and res["inputs"]["F"]["dependent_on_indexer"]
    assert res["services_summary"].startswith("CRITICAL · INDEXER_FAILED")
    # Auth telemetry is never folded under the indexer.
    assert "dependent_on_indexer" not in res["inputs"]["T"]


# M ------------------------------------------------------------------------------------------
def test_manager_down_core_daemon_and_optional_daemons():
    assert state(ev(healthy(mgr__unit="inactive")), "M") == "CRITICAL"
    core = ev(healthy(mgr__daemon__analysisd="stopped"))
    assert state(core, "M") == "CRITICAL" and "CORE_DAEMON_DOWN" in reasons(core, "M")
    assert "wazuh-analysisd" in core["core_down"]
    tier2 = ev(healthy(mgr__daemon__apid="stopped"))
    assert state(tier2, "M") == "DEGRADED" and "DAEMON_DOWN" in reasons(tier2, "M")
    # maild, clusterd and the like are off by design and never count.
    assert state(ev(healthy(mgr__daemon__clusterd="stopped")), "M") == "NOMINAL"


def test_manager_api_and_output_age():
    assert "API_DOWN" in reasons(ev(healthy(mgr__api_http="000")), "M")
    assert state(ev(healthy(mgr__alerts_mtime=NOW - 7 * 3600)), "M") == "DEGRADED"
    assert state(ev(healthy(mgr__alerts_mtime=NOW - 25 * 3600)), "M") == "CRITICAL"
    assert state(ev(healthy(mgr__unit=None)), "M") == "UNKNOWN"


# 10: agents -----------------------------------------------------------------------------------
def test_expected_list_is_tracked_and_seeded():
    assert len(EXPECTED) == 10 and len({e["id"] for e in EXPECTED}) == 10
    q = next(e for e in EXPECTED if e["name"] == "quixote")
    assert q["required"] is False and q["auth"] == "none"
    for name in ("pve1", "Jarvis"):
        e = next(x for x in EXPECTED if x["name"] == name)
        assert e["canary"] is False and e["auth_s"] == 24 * 3600
    for e in EXPECTED:
        if e["name"] not in ("pve1", "Jarvis", "quixote"):
            assert e["canary"] is True and e["auth_s"] == 2 * 3600, e


def test_all_expected_agents_present_is_nominal():
    assert state(ev(healthy()), "A") == "NOMINAL"


def test_one_missing_agent_is_a_failure_state():
    res = ev(healthy(**{f"agent__{BY_NAME['pve4']}__status": "Disconnected"}))
    assert state(res, "A") == "DEGRADED" and "AGENT_MISSING" in reasons(res, "A")
    assert res["inputs"]["A"]["missing"] == [BY_NAME["pve4"]] and res["overall"] != "NOMINAL"


def test_majority_of_required_agents_missing_is_critical():
    over = {f"agent__{e['id']}__status": "Disconnected" for e in EXPECTED[1:6]}
    res = ev(healthy(**over))
    assert state(res, "A") == "CRITICAL" and "AGENTS_MAJORITY_MISSING" in reasons(res, "A")


def test_unknown_extra_agent_is_flagged():
    res = ev(healthy(agent__010__name="intruder", agent__010__status="Active", agents__listed=11))
    assert state(res, "A") == "DEGRADED" and "AGENT_UNEXPECTED" in reasons(res, "A")
    assert res["inputs"]["A"]["unexpected"] == ["010"]


def test_renamed_agent_id_is_flagged():
    res = ev(healthy(**{f"agent__{BY_NAME['pve2']}__name": "notpve2"}))
    assert "AGENT_IDENTITY_MISMATCH" in reasons(res, "A") and state(res, "A") == "DEGRADED"


def test_optional_workstation_offline_is_information_only():
    res = ev(healthy(**{f"agent__{BY_NAME['quixote']}__status": "Disconnected"}))
    assert state(res, "A") == "NOMINAL" and "AGENT_OPTIONAL_OFFLINE" in reasons(res, "A")


def test_malformed_agent_list_is_unknown():
    over = {f"agent__{e['id']}__status": None for e in EXPECTED}
    over.update({f"agent__{e['id']}__name": None for e in EXPECTED})
    res = ev(healthy(agents__listed=0, **over))
    assert state(res, "A") == "UNKNOWN" and res["integrity"] == "UNKNOWN"


def test_unreadable_expected_list_is_unknown_not_nominal():
    res = ev(healthy(), expected=None)
    assert state(res, "A") == "UNKNOWN" and state(res, "T") == "UNKNOWN"
    assert res["integrity"] == "UNKNOWN"


# 11 to 14: auth telemetry ---------------------------------------------------------------------
def test_active_agent_with_stale_auth_is_not_nominal():
    pve4 = BY_NAME["pve4"]
    res = ev(healthy(**{f"auth__{pve4}__canary": NOW - 3 * 3600, f"auth__{pve4}__any": NOW - 3 * 3600}))
    assert state(res, "A") == "NOMINAL"
    assert state(res, "T") == "DEGRADED" and res["inputs"]["T"]["stale"] == [pve4]
    assert res["overall"] != "NOMINAL"


def test_monitor_login_within_two_hours_is_fresh():
    pve3 = BY_NAME["pve3"]
    res = ev(healthy(**{f"auth__{pve3}__canary": NOW - 7199}))
    assert state(res, "T") == "NOMINAL"
    assert state(ev(healthy(**{f"auth__{pve3}__canary": NOW - 7201})), "T") == "DEGRADED"


def test_canary_host_is_judged_on_the_canary_not_on_any_login():
    """A canary host whose monitor login stopped is stale even if another 5715 exists."""
    q = BY_NAME["QuarkyLab"]
    res = ev(healthy(**{f"auth__{q}__canary": NOW - 5 * 3600, f"auth__{q}__any": NOW - 60}))
    assert state(res, "T") == "DEGRADED" and res["inputs"]["T"]["stale"] == [q]


def test_exception_hosts_use_twenty_four_hours_on_any_login():
    j, p1 = BY_NAME["Jarvis"], BY_NAME["pve1"]
    fresh = ev(healthy(**{f"auth__{j}__any": NOW - 20 * 3600, f"auth__{j}__canary": 0}))
    assert state(fresh, "T") == "NOMINAL"
    stale = ev(healthy(**{f"auth__{p1}__any": NOW - 25 * 3600}))
    assert state(stale, "T") == "DEGRADED" and stale["inputs"]["T"]["stale"] == [p1]


def test_no_auth_event_ever_is_stale():
    pve5 = BY_NAME["pve5"]
    res = ev(healthy(**{f"auth__{pve5}__canary": 0, f"auth__{pve5}__any": 0}))
    assert pve5 in res["inputs"]["T"]["stale"]


def test_stale_majority_is_critical_and_one_is_degraded():
    hosts = [e for e in EXPECTED if e["auth"] == "journald"]
    over = {}
    for e in hosts[:5]:
        over[f"auth__{e['id']}__canary"] = NOW - 9 * 3600
        over[f"auth__{e['id']}__any"] = NOW - 30 * 3600
    res = ev(healthy(**over))
    assert state(res, "T") == "CRITICAL" and "AUTH_MAJORITY_STALE" in reasons(res, "T")


def test_quixote_has_no_auth_freshness_requirement():
    q = BY_NAME["quixote"]
    res = ev(healthy(**{f"auth__{q}__any": 0, f"auth__{q}__canary": 0}))
    assert state(res, "T") == "NOMINAL"


def test_auth_scan_failure_is_unknown():
    assert state(ev(healthy(auth__scan="failed")), "T") == "UNKNOWN"
    assert state(ev(healthy(auth__scan="partial")), "T") == "UNKNOWN"
    assert state(ev(healthy(**{f"auth__{BY_NAME['pve2']}__canary": None})), "T") == "UNKNOWN"


# 15: drops ------------------------------------------------------------------------------------
PREV = {"events_dropped": 10, "events_received": 1000, "discarded": 0, "delta_lost": 0}


def test_increasing_drops_are_a_failure_state():
    res = ev(healthy(x__events_dropped=12, x__events_received=2000), prev=PREV)
    assert state(res, "X") == "DEGRADED" and "EVENTS_DROPPED" in reasons(res, "X")
    assert res["inputs"]["X"]["delta_dropped"] == 2


def test_drops_above_one_percent_or_two_intervals_running_are_critical():
    heavy = ev(healthy(x__events_dropped=40, x__events_received=2000), prev=PREV)
    assert state(heavy, "X") == "CRITICAL" and "EVENTS_DROPPED_SUSTAINED" in reasons(heavy, "X")
    again = ev(healthy(x__events_dropped=11, x__events_received=2000), prev={**PREV, "delta_lost": 3})
    assert state(again, "X") == "CRITICAL"


def test_remoted_discards_count_as_drops():
    res = ev(healthy(x__events_dropped=10, x__events_received=2000, x__discarded=1), prev=PREV)
    assert state(res, "X") == "DEGRADED"


def test_historical_drops_without_growth_are_not_current():
    res = ev(healthy(x__events_dropped=10, x__events_received=2000), prev=PREV)
    assert state(res, "X") == "NOMINAL" and res["inputs"]["X"]["delta_dropped"] == 0


def test_first_sample_and_counter_reset():
    assert state(ev(healthy()), "X") == "NOMINAL"                  # no prev, counters 0
    first = ev(healthy(x__events_dropped=10))                      # no prev, historical drops
    assert state(first, "X") == "UNKNOWN" and "DROPS_RATE_UNMEASURED" in reasons(first, "X")
    reset = ev(healthy(x__events_dropped=3, x__events_received=50), prev=PREV)
    assert state(reset, "X") == "UNKNOWN"
    clean_reset = ev(healthy(x__events_dropped=0, x__events_received=50), prev=PREV)
    assert state(clean_reset, "X") == "NOMINAL"


def test_queue_saturation():
    assert state(ev(healthy(x__queue_max="0.75")), "X") == "DEGRADED"
    assert state(ev(healthy(x__remoted_queue="0.96")), "X") == "CRITICAL"
    assert state(ev(healthy(x__events_dropped=None)), "X") == "UNKNOWN"


# 16 and 17: malformed wrapper output and UNKNOWN ----------------------------------------------
def test_malformed_wrapper_output_is_unknown():
    for kv in ({}, {"schema": "other/v9", "end": "1"}, {k: v for k, v in healthy().items() if k != "end"},
               WH.parse_kv("garbage\nnot a report\n<error: boom>")):
        res = ev(kv)
        assert res["overall"] == res["services"] == res["integrity"] == "UNKNOWN", kv
        assert res["measured"] is False


def test_parse_kv_ignores_injected_text():
    kv = WH.parse_kv("schema=x\nmgr.unit=active; rm -rf /\nidx.health=green\n  idx.http=401  \n"
                     "Mgr.Unit=active\n")
    assert kv == {"schema": "x", "idx.health": "green", "idx.http": "401"}


def test_unknown_is_never_green():
    assert WH.verdict("UNKNOWN") == "UNKNOWN" and WH.verdict("not-a-state") == "UNKNOWN"
    assert mon.VERDICT_RANK["UNKNOWN"] > mon.VERDICT_RANK["OK"]
    assert mon.VERDICT_RANK["CRIT"] > mon.VERDICT_RANK["WARN"]
    assert mon.VERDICT_RANK.get("SOMETHING-NEW", mon.VERDICT_RANK_DEFAULT) > mon.VERDICT_RANK["OK"]
    assert WH.worst(["NOMINAL", "UNKNOWN"]) == "UNKNOWN"
    assert WH.worst(["UNKNOWN", "DEGRADED"]) == "DEGRADED"   # a measured fault always shows
    assert WH.worst([]) == "UNKNOWN"
    assert mon.classify("wazuh", 0, "") == "UNKNOWN"
    assert mon.classify("wazuh", 0, "wazuh-analysisd is running") == "UNKNOWN"


# 18: the real broken state ---------------------------------------------------------------------
def test_known_degraded_state_of_2026_10_02_is_critical():
    res = ev(broken_2026_10_02())
    assert res["overall"] == "CRITICAL"
    assert res["services"] == "CRITICAL" and res["integrity"] == "CRITICAL"
    assert state(res, "M") == "NOMINAL"                     # what the old check saw
    assert state(res, "I") == "CRITICAL" and state(res, "T") == "CRITICAL"
    assert state(res, "A") == "NOMINAL"                     # agents Active, yet blind
    assert res["services_summary"].startswith("CRITICAL · INDEXER_FAILED")
    assert "AUTH_MAJORITY_STALE" in res["integrity_summary"]
    assert len(res["inputs"]["T"]["stale"]) == 8


# monitor integration --------------------------------------------------------------------------
def _report(kv):
    out = "\n".join(f"{k}={v}" for k, v in kv.items())
    mon._WAZUH_CACHE.clear()
    mon._WAZUH_CACHE.update({"expected": EXPECTED, "prev": None})
    verdict = mon.classify("wazuh", 0, out)
    metrics = mon.PARSERS["wazuh"](out)
    check = {"verdict": verdict, "rc": 0, "metrics": metrics, "raw_excerpt": ""}
    return {"nodes": {"wazuh": {"wazuh": check, "wazuh_coverage": mon.wazuh_coverage(check)}}}


def test_monitor_splits_services_and_integrity_checks():
    rep = _report(broken_2026_10_02())
    assert rep["nodes"]["wazuh"]["wazuh"]["verdict"] == "CRIT"
    assert rep["nodes"]["wazuh"]["wazuh_coverage"]["verdict"] == "CRIT"
    ok = _report(healthy())
    assert ok["nodes"]["wazuh"]["wazuh"]["verdict"] == "OK"
    assert ok["nodes"]["wazuh"]["wazuh_coverage"]["verdict"] == "OK"
    mixed = _report(healthy(**{f"auth__{BY_NAME['pve4']}__canary": NOW - 5 * 3600}))
    assert mixed["nodes"]["wazuh"]["wazuh"]["verdict"] == "OK"
    assert mixed["nodes"]["wazuh"]["wazuh_coverage"]["verdict"] == "WARN"


def test_coverage_of_a_failed_run_is_unknown():
    cov = mon.wazuh_coverage({"verdict": "AUTH-FAIL", "rc": 1, "metrics": {}})
    assert cov["verdict"] == "UNKNOWN" and cov["metrics"]["state"] == "UNKNOWN"
    assert mon.wazuh_coverage(None)["verdict"] == "UNKNOWN"


def test_check_reason_is_bounded_and_specific():
    rep = _report(broken_2026_10_02())
    w = rep["nodes"]["wazuh"]
    assert mon.check_reason("wazuh", w["wazuh"]["metrics"]) == "INDEXER_FAILED"
    assert mon.check_reason("wazuh_coverage", w["wazuh_coverage"]["metrics"]) == "AUTH_MAJORITY_STALE"
    assert mon.check_reason("wazuh", _report(healthy())["nodes"]["wazuh"]["wazuh"]["metrics"]) == ""


def test_textfile_export_carries_both_trees_and_the_inputs():
    text = mon.render_metrics(_report(broken_2026_10_02()), now=NOW)
    assert 'netframe_monitor_check_status{node="wazuh",check="wazuh",state="crit",reason="INDEXER_FAILED"} 1' in text
    assert 'check="wazuh_coverage",state="crit",reason="AUTH_MAJORITY_STALE"} 1' in text
    assert 'netframe_wazuh_siem_state{tree="overall",state="critical"} 1' in text
    assert 'netframe_wazuh_input_state{input="indexer",state="critical"} 1' in text
    assert 'netframe_wazuh_input_state{input="manager",state="nominal"} 1' in text
    assert 'netframe_wazuh_indexer_phase{phase="failed"} 1' in text
    assert 'netframe_wazuh_auth_last_seen_timestamp_seconds{agent="pve1"}' in text
    assert "netframe_wazuh_health_measured 1" in text
    # one-hot: exactly one state per tree and per input
    for tree in ("overall", "services", "integrity"):
        on = re.findall(rf'netframe_wazuh_siem_state{{tree="{tree}",state="\w+"}} 1', text)
        assert len(on) == 1, tree
    for name in WH.INPUT_NAME.values():
        on = re.findall(rf'netframe_wazuh_input_state{{input="{name}",state="\w+"}} 1', text)
        assert len(on) == 1, name


def test_history_flattening_feeds_the_next_drop_delta():
    rep = _report(healthy(x__events_dropped=7, x__events_received=900))
    flat = mon.flatten_metrics(rep["nodes"])
    assert flat["wazuh.wazuh.services"] == 0 and flat["wazuh.wazuh.indexer"] == 0
    prev = WH.prev_from_flat(flat, "wazuh.wazuh")
    assert prev == {"events_dropped": 7, "events_received": 900, "discarded": 0, "delta_lost": 0}
    assert flat["wazuh.wazuh.indexer_start_duration_s"] == 242


def test_evidence_consumer_still_sees_core_down():
    res = ev(healthy(mgr__daemon__remoted="stopped"))
    assert "wazuh-remoted" in res["core_down"]


def _drive_main(monkeypatch, tmp_path, node_outputs):
    """Run the REAL main() over fake nodes. node_outputs: [(host, check, rc, out)] in NODES order."""
    nodes, outs = {}, {}
    for host, check, rc, out in node_outputs:
        nodes.setdefault(host, {"ip": f"198.51.100.{len(nodes) + 1}", "checks": {}})["checks"][check] = check
        outs[(nodes[host]["ip"], check)] = (rc, out)
    history = []
    monkeypatch.setattr(mon, "NODES", nodes)
    monkeypatch.setattr(mon, "run", lambda ip, command: outs[(ip, command)])
    monkeypatch.setattr(mon, "STATE_FILE", str(tmp_path / "last_run.json"))
    monkeypatch.setattr(mon, "export_metrics", lambda report: None)
    monkeypatch.setattr(mon, "append_history", history.append)
    mon._WAZUH_CACHE.clear()
    mon._WAZUH_CACHE.update({"expected": EXPECTED, "prev": None})
    rc = mon.main()
    return rc, json.load(open(tmp_path / "last_run.json")), history


def _blind_majority():
    kv = healthy(**{f"auth__{BY_NAME[n]}__{f}": 0 for n in ("pve2", "pve3", "pve4", "pve5", "Randy")
                    for f in ("canary", "any")})
    return "\n".join(f"{k}={v}" for k, v in kv.items())


def test_a_measured_crit_never_hides_a_later_collection_failure(monkeypatch, tmp_path):
    """Since Packet C, CRIT ranks with AUTH-FAIL. The run's exit status must still say a check could
    not be collected, and the headline must name the blind check, whichever node comes first."""
    rc, rep, hist = _drive_main(monkeypatch, tmp_path, [
        ("wazuh", "wazuh", 0, _blind_majority()),
        ("pve3", "df", 255, "monitor@198.51.100.2: Permission denied (publickey)."),
    ])
    assert rep["nodes"]["wazuh"]["wazuh_coverage"]["verdict"] == "CRIT"
    assert rep["nodes"]["pve3"]["df"]["verdict"] == "AUTH-FAIL"
    assert rc == 1, "a collection failure must fail the run even after a measured CRIT"
    assert rep["worst"] == "AUTH-FAIL" and hist[0]["worst"] == "AUTH-FAIL"


def test_a_measured_crit_alone_does_not_fail_the_run(monkeypatch, tmp_path):
    """CRIT is a measured state of the estate, not a broken collector: the unit stays successful, and
    the headline still says CRIT."""
    rc, rep, _ = _drive_main(monkeypatch, tmp_path, [("wazuh", "wazuh", 0, _blind_majority())])
    assert rc == 0 and rep["worst"] == "CRIT"


def test_a_collection_failure_first_still_fails_the_run(monkeypatch, tmp_path):
    rc, rep, _ = _drive_main(monkeypatch, tmp_path, [
        ("pve3", "df", 255, "monitor@198.51.100.1: Permission denied (publickey)."),
        ("wazuh", "wazuh", 0, _blind_majority()),
    ])
    assert rc == 1 and rep["worst"] == "AUTH-FAIL"


# the wrapper, executed against a fake host ----------------------------------------------------
WRAPPER = os.path.join(BASE, "node-local", "azuh-nfm-wazuh-health")
LINE = re.compile(r"^[a-z0-9_.]+=[A-Za-z0-9_./:-]*$")


def _wrapper():
    loader = importlib.machinery.SourceFileLoader("azuh_nfm_wazuh_health", WRAPPER)
    spec = importlib.util.spec_from_loader("azuh_nfm_wazuh_health", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def _alert(rule, agent_id, name, ts, log, location="journald", compact=True):
    """One alert line. Real alerts.json is compact JSON; spaced lines are mixed in deliberately."""
    return json.dumps(separators=(",", ":") if compact else None, obj={"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                       "rule": {"id": rule, "level": 3}, "agent": {"id": agent_id, "name": name},
                       "location": location, "full_log": log}) + "\n"


def _fake_host(tmp_path, wr, indexer="active"):
    now = datetime.fromtimestamp(NOW, timezone.utc)
    alerts = tmp_path / "alerts" / "alerts.json"
    alerts.parent.mkdir(parents=True)
    canary = "Accepted publickey for monitor from 192.168.10.31 port 4022 ssh2: ED25519 SHA256:abc"
    alerts.write_text(
        _alert("5715", "007", "pve4", now - timedelta(minutes=10), f"Oct 03 pve4 sshd[1]: {canary}")
        + _alert("5715", "008", "Jarvis", now - timedelta(hours=1),
                 "Oct 03 Jarvis sshd[2]: Accepted publickey for root from 192.168.10.152 port 1 ssh2",
                 compact=False)
        # A different rule whose text merely mentions 5715 must not count.
        + _alert("5501", "003", "Randy", now - timedelta(minutes=3),
                 "Oct 03 Randy sshd[9]: Accepted publickey for monitor from 192.168.10.31 port 5715 ssh2")
        # A user-journal session line and a sudo line on QuarkyLab: neither proves the system journal.
        + _alert("5501", "005", "QuarkyLab", now - timedelta(minutes=1),
                 "Oct 03 QuarkyLab sshd-session[3]: pam_unix(sshd:session): session opened for user x")
        + _alert("5402", "005", "QuarkyLab", now - timedelta(minutes=1), "Oct 03 QuarkyLab sudo: x : COMMAND=/bin/ls")
        # A cron session line that somehow carries rule 5715 must still never count.
        + _alert("5715", "006", "pve5", now - timedelta(minutes=2),
                 "Oct 03 pve5 CRON[4]: Accepted pam_unix(cron:session): session opened for user root")
        + "not json at all\n")
    y = now - timedelta(days=1)
    ydir = tmp_path / "alerts" / y.strftime("%Y") / y.strftime("%b")
    ydir.mkdir(parents=True)
    with gzip.open(ydir / f"ossec-alerts-{y:%d}.json.gz", "wt") as fh:
        fh.write(_alert("5715", "001", "pve1", now - timedelta(hours=20),
                        "Oct 02 pve1 sshd[5]: Accepted publickey for root from 192.168.10.152 port 2 ssh2"))
    (tmp_path / "analysisd.state").write_text(
        "# State file\nevents_received='5000'\nevents_dropped='3'\nevent_queue_usage='0.10'\n"
        "alerts_queue_usage='0.40'\n")
    (tmp_path / "remoted.state").write_text("queue_size='10'\ntotal_queue_size='100'\ndiscarded_count='1'\n"
                                            "evt_count='777'\n")
    (tmp_path / "cluster.log").write_text(
        "[2026-09-26T19:07:13,360][INFO ][o.o.g.GatewayService] [node-1] recovered [139] indices\n"
        "[2026-09-26T19:18:31,992][INFO ][o.o.c.r.a.AllocationService] [node-1] Cluster health status "
        "changed from [RED] to [GREEN] (reason: [shards started [[x][0]]]).\n")
    stamp = lambda s: (now - timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%S.000Z")  # noqa: E731
    (tmp_path / "filebeat").write_text(
        f"{stamp(3000)}\tERROR\tpipeline/output.go:154\tFailed to connect to backoff(elasticsearch(x)): old\n"
        f"{stamp(120)}\tERROR\tpipeline/output.go:154\tFailed to connect to backoff(elasticsearch(x)): new\n"
        f"{stamp(60)}\tINFO\tpipeline/output.go:151\tConnection to backoff(elasticsearch(x)) established\n")
    ino = os.stat(alerts).st_ino
    size = os.path.getsize(alerts)
    reg = tmp_path / "log.json"
    reg.write_text('{"op":"set","id":1}\n'
                   + json.dumps({"k": "x", "v": {"offset": size - 100, "FileStateOS": {"inode": ino, "device": 1}}})
                   + "\n" + json.dumps({"k": "y", "v": {"offset": 5, "FileStateOS": {"inode": ino + 1}}}) + "\n")
    for attr, p in (("ALERTS", alerts), ("ALERTS_DIR", tmp_path / "alerts"),
                    ("ANALYSISD_STATE", tmp_path / "analysisd.state"),
                    ("REMOTED_STATE", tmp_path / "remoted.state"), ("CLUSTER_LOG", tmp_path / "cluster.log"),
                    ("FILEBEAT_LOG", tmp_path / "filebeat"), ("FILEBEAT_REGISTRY", reg),
                    ("INDEXER_CERT", tmp_path / "admin.pem"), ("INDEXER_KEY", tmp_path / "admin-key.pem")):
        setattr(wr, attr, str(p))
    (tmp_path / "admin.pem").write_text("cert")
    (tmp_path / "admin-key.pem").write_text("SECRET-KEY-MATERIAL-MUST-NEVER-BE-PRINTED")
    up = 500_000.0
    agent_list = ("\nWazuh agent_control. List of available agents:\n"
                  + "".join(f"   ID: {e['id']}, Name: {e['name']}{' (server)' if e['id'] == '000' else ''}, "
                            f"IP: any, {'Active/Local' if e['id'] == '000' else 'Active'}\n" for e in EXPECTED)
                  + "\nList of agentless devices:\n")
    calls = []

    def fake_run(argv, timeout=15):
        calls.append(list(argv))
        a = " ".join(argv)
        if argv[0] == wr.SYSTEMCTL and argv[1] == "is-active":
            return 0, "active\n"
        if argv[0] == wr.SYSTEMCTL and argv[1] == "show":
            mono = lambda ago: str(int((up - ago) * 1e6))  # noqa: E731
            return 0, (f"ActiveState={indexer}\nSubState=running\nResult=success\nNRestarts=0\n"
                       f"TimeoutStartUSec=7min\nExecMainStartTimestampMonotonic={mono(86400 + 242)}\n"
                       f"ActiveEnterTimestampMonotonic={mono(86400)}\nStateChangeTimestampMonotonic={mono(86400)}\n")
        if argv[0] == wr.WAZUH_CONTROL:
            return 1, ("wazuh-clusterd not running...\nwazuh-modulesd is running...\nwazuh-analysisd is running...\n"
                       "wazuh-remoted is running...\nwazuh-db is running...\nwazuh-syscheckd is running...\n"
                       "wazuh-logcollector is running...\nwazuh-monitord is running...\nwazuh-execd is running...\n"
                       "wazuh-authd is running...\nwazuh-apid is running...\nwazuh-maild not running...\n")
        if argv[0] == wr.JOURNALCTL:
            return 0, "Starting wazuh-indexer...\nStarted wazuh-indexer.\n"
        if argv[0] == wr.AGENT_CONTROL:
            return 0, agent_list
        if argv[0] == wr.CURL and "_cluster/health" in a:
            return 0, '{"status":"green"}'
        if argv[0] == wr.CURL and ":9200/" in a:
            return 0, "401"
        if argv[0] == wr.CURL and ":55000/" in a:
            return 0, "401"
        if argv[0] == wr.CURL:
            return 0, "302"
        return 127, ""

    wr.run = fake_run
    wr.uptime_s = lambda: up
    wr.time = types.SimpleNamespace(time=lambda: float(NOW))
    wr.OUT.clear()
    return calls


def _run_wrapper(wr, capsys, argv=("nfm-wazuh-health",)):
    rc = wr.main(list(argv))
    return rc, capsys.readouterr().out


def test_wrapper_refuses_arguments(capsys):
    wr = _wrapper()
    rc, out = _run_wrapper(wr, capsys, ("nfm-wazuh-health", "--anything"))
    assert rc == 2 and "err.args=REFUSED" in out and "schema=" not in out


def test_wrapper_emits_only_the_bounded_vocabulary(tmp_path, capsys):
    wr = _wrapper()
    calls = _fake_host(tmp_path, wr)
    rc, out = _run_wrapper(wr, capsys)
    assert rc == 0
    lines = out.strip().splitlines()
    assert lines[0] == f"schema={WH.SCHEMA}" and lines[-1] == "end=1"
    assert all(LINE.match(x) for x in lines), [x for x in lines if not LINE.match(x)]
    assert "SECRET-KEY-MATERIAL" not in out and "Accepted" not in out and "192.168" not in out
    # read-only: nothing but fixed read commands was executed
    for argv in calls:
        assert argv[0] in (wr.SYSTEMCTL, wr.JOURNALCTL, wr.CURL, wr.WAZUH_CONTROL, wr.AGENT_CONTROL)
        if argv[0] == wr.SYSTEMCTL:
            assert argv[1] in ("is-active", "show")
        if argv[0] == wr.WAZUH_CONTROL:
            assert argv[1:] == ["status"]
        if argv[0] == wr.CURL:
            assert "-X" not in argv and "-d" not in argv and "--data" not in argv


def test_wrapper_auth_scan_counts_only_system_journal_successes(tmp_path, capsys):
    wr = _wrapper()
    _fake_host(tmp_path, wr)
    kv = WH.parse_kv(_run_wrapper(wr, capsys)[1])
    assert kv["auth.scan"] == "ok"
    assert int(kv["auth.007.canary"]) == NOW - 600 and int(kv["auth.007.any"]) == NOW - 600
    assert int(kv["auth.008.any"]) == NOW - 3600 and kv["auth.008.canary"] == "0"
    # QuarkyLab had only a session line and a sudo line: no proof of the system journal.
    assert kv["auth.005.any"] == "0" and kv["auth.005.canary"] == "0"
    # The cron:session line never counts, even carrying rule 5715.
    assert kv["auth.006.any"] == "0"
    # Rule 5501 is not 5715 even when its text contains the canary and the digits 5715.
    assert kv["auth.003.any"] == "0" and kv["auth.003.canary"] == "0"
    # pve1's only success was yesterday: the 24 h window reaches into yesterday's archive.
    assert int(kv["auth.001.any"]) == NOW - 20 * 3600


def test_wrapper_report_classifies_end_to_end(tmp_path, capsys):
    wr = _wrapper()
    _fake_host(tmp_path, wr)
    kv = WH.parse_kv(_run_wrapper(wr, capsys)[1])
    assert kv["idx.unit"] == "active" and kv["idx.health"] == "green" and kv["idx.http"] == "401"
    assert int(kv["idx.active_enter"]) - int(kv["idx.exec_start"]) == 242
    assert kv["idx.timeout_start_s"] == "420"
    assert kv["mgr.daemon.analysisd"] == "running" and kv["mgr.daemon.maild"] == "stopped"
    assert kv["x.events_dropped"] == "3" and kv["x.discarded"] == "1" and kv["x.remoted_queue"] == "0.10"
    assert kv["fb.connect_failures_15m"] == "1" and kv["fb.lag_bytes"] == "100"
    assert kv["agent.000.name"] == "azuh" and kv["agent.000.status"] == "Active/Local"
    assert kv["idx.health_change_to"] == "green"
    res = ev(kv)
    assert state(res, "I") == "NOMINAL" and state(res, "M") == "NOMINAL" and state(res, "A") == "NOMINAL"
    assert state(res, "F") == "DEGRADED"                     # one connect failure in the last 15 min
    assert state(res, "T") == "CRITICAL"                     # only pve4, Jarvis and pve1 are fresh
    assert state(res, "X") == "UNKNOWN"                      # historical drops, no previous sample


def test_wrapper_failed_indexer_and_missing_files(tmp_path, capsys):
    wr = _wrapper()
    _fake_host(tmp_path, wr, indexer="failed")
    os.remove(wr.ANALYSISD_STATE)
    kv = WH.parse_kv(_run_wrapper(wr, capsys)[1])
    assert kv["idx.unit"] == "failed"
    assert kv["err.x"] == "ANALYSISD_STATE_UNREADABLE" and kv["end"] == "1"
    res = ev(kv)
    assert state(res, "I") == "CRITICAL" and state(res, "X") == "UNKNOWN"


def test_timespan_parser():
    wr = _wrapper()
    assert wr.timespan_s("7min") == 420 and wr.timespan_s("3min") == 180
    assert wr.timespan_s("1min 30s") == 90 and wr.timespan_s("infinity") == -1
    assert wr.timespan_s("") == -1


def test_sudoers_source_pins_no_arguments():
    text = open(os.path.join(BASE, "node-local", "azuh-nfm-wazuh-health.sudoers")).read()
    rules = [x for x in text.splitlines() if x and not x.startswith("#")]
    assert rules == ['monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-wazuh-health ""']


# the wall contract ----------------------------------------------------------------------------
# netframe-dashboard renders these two checks. It carries a byte-identical copy of this fixture and
# pins its sha256, so the shape cannot change on one side only. The fixture is GENERATED by this
# repository's own classifier; a hand-written example would drift silently.
WALL_FIXTURE = os.path.join(BASE, "tests", "fixtures", "wazuh-health-checks-v1.json")


def build_wall_fixture():
    scenarios = {
        "healthy": healthy(),
        "broken_2026_10_02": broken_2026_10_02(),
        "recovering_4min_after_ready": healthy(idx__active_enter=NOW - 240, idx__exec_start=NOW - 482,
                                               idx__health="red", dash__http="503"),
        "auth_stale_agents_active": healthy(**{f"auth__{BY_NAME['pve4']}__canary": NOW - 5 * 3600}),
        "unmeasured": {"garbage": "1"},
    }
    out = {"_comment": "GENERATED by netframe-monitor tests/test_wazuh_health.py build_wall_fixture(). "
                       "nodes.wazuh of last_run.json per scenario. Do not edit by hand.",
           "schema": WH.SCHEMA, "scenarios": {}}
    for name, kv in scenarios.items():
        rep = _report(kv)
        out["scenarios"][name] = rep["nodes"]["wazuh"]
    return json.dumps(out, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def test_wall_fixture_is_current():
    with open(WALL_FIXTURE, encoding="utf-8") as fh:
        assert fh.read() == build_wall_fixture(), "regenerate tests/fixtures/wazuh-health-checks-v1.json"


def test_summary_never_repeats_a_reason():
    res = WH.unmeasured()
    assert res["services_summary"] == "UNKNOWN · HEALTH_UNMEASURED"
    words = res["integrity_summary"].split(" · ")
    assert len(words) == len(set(words))
