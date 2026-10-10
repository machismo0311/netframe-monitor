"""guest_state: hypervisor guest state per Proxmox node, keyed by VMID (pve5 first).

These assert that guest state is reported truthfully and cannot be mistaken for anything else: a
paused VM is PAUSED (not running), a guest absent from a good collection is MISSING (not STOPPED), a
failed, stale, malformed or suspiciously empty collection is UNKNOWN (never OK, never "all missing"),
extra and renamed guests stay visible, onboot=0 guests are never alerted, pve5 never emits the legacy
`guests` check the live wall paints green, and a running guest never yields any application-level
field. The wrapper is exercised against a stub pvesh and a fake /etc/pve tree.

Run: python3 -m pytest tests/test_guest_state.py -q
"""
import importlib.machinery
import importlib.util
import json
import os
import stat
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(mod):
    spec = importlib.util.spec_from_file_location(mod, os.path.join(BASE, f"{mod}.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


GS = _load("netframe_guest_state")
mon = _load("netframe_monitor")
INVENTORY_PATH = os.path.join(BASE, "node-local", "pve-expected-guests.psv")
INV = GS.load_inventory(INVENTORY_PATH)
NOW = 1_790_000_000


def g(vmid, kind, name, status="running", qmp=None, onboot=1, lock=None):
    if kind == "qemu" and qmp is None and status == "running":
        qmp = "running"
    return {"vmid": vmid, "type": kind, "name": name, "status": status,
            "qmpstatus": qmp if kind == "qemu" else None, "lock": lock, "onboot": onboot}


def healthy_guests():
    return [g(105, "lxc", "headscale"), g(108, "lxc", "netframe-pihole2"),
            g(110, "qemu", "homeassistant"), g(112, "lxc", "minecraft")]


def doc(guests=None, node="pve5", ok=True, error=None, collected_at=NOW - 2, schema=GS.SCHEMA):
    return json.dumps({"schema": schema, "node": node, "collected_at": collected_at, "ok": ok,
                       "error": error, "guests": healthy_guests() if guests is None else guests})


def ev(out, rc=0, host="pve5", inventory=INV, now=NOW):
    return GS.evaluate(out, rc=rc, host=host, now=now, inventory=inventory)


def replace(guests, vmid, **kw):
    out = []
    for x in guests:
        if x["vmid"] == vmid:
            x = {**x, **kw}
        out.append(x)
    return out


# --- the tracked inventory --------------------------------------------------------------------
def test_inventory_is_tracked_keyed_by_vmid_and_pve5_only():
    assert set(INV) == {"pve5"}, "other nodes are not migrated yet"
    assert INV["pve5"] == {105: {"type": "lxc", "name": "headscale"},
                           108: {"type": "lxc", "name": "netframe-pihole2"},
                           110: {"type": "qemu", "name": "homeassistant"},
                           112: {"type": "lxc", "name": "minecraft"}}


def test_inventory_validation_refuses_malformed_files(tmp_path):
    head = "node|vmid|type|name|notes\n"
    bad = {"wrong header": "node|id|type|name|notes\npve5|1|lxc|a|\n",
           "field count": head + "pve5|1|lxc|a\n",
           "vmid": head + "pve5|abc|lxc|a|\n",
           "type": head + "pve5|1|vm|a|\n",
           "empty name": head + "pve5|1|lxc||\n",
           "duplicate": head + "pve5|1|lxc|a|\npve5|1|lxc|b|\n",
           "empty": "# only a comment\n" + head}
    for label, text in bad.items():
        p = tmp_path / "inv.psv"
        p.write_text(text)
        try:
            GS.load_inventory(str(p))
        except ValueError:
            continue
        raise AssertionError(f"accepted a malformed inventory: {label}")


def test_unreadable_inventory_is_unknown_never_ok():
    m = ev(doc(), inventory=None)
    assert m["verdict"] == "UNKNOWN" and m["reason"] == "INVENTORY_UNREADABLE"
    assert m["collection"] == "OK"                       # the collection itself was fine


def test_node_without_inventory_rows_is_unknown():
    m = ev(doc(node="pve3"), host="pve3")
    assert m["verdict"] == "UNKNOWN" and m["reason"] == "NO_INVENTORY_FOR_NODE"
    assert [e["vmid"] for e in m["extra"]] == [105, 108, 110, 112]


# --- the contract ----------------------------------------------------------------------------
def test_all_four_running_is_ok():
    m = ev(doc())
    assert m["verdict"] == "OK" and m["reason"] == "" and m["collection"] == "OK"
    assert m["counts"] == {"RUNNING": 4, "STOPPED": 0, "PAUSED": 0, "MISSING": 0, "UNKNOWN": 0}
    assert set(m["guests"]) == {"105", "108", "110", "112"}
    assert m["guests"]["110"] == {"name": "homeassistant", "type": "qemu", "state": "RUNNING",
                                  "raw_status": "running", "qmpstatus": "running", "lock": None,
                                  "onboot": 1, "expected": True, "expected_name": "homeassistant"}
    assert m["missing"] == [] and m["extra"] == [] and m["renamed"] == []
    assert m["age_s"] == 2 and m["collected_at"] == NOW - 2
    assert m["schema"] == GS.SCHEMA and m["node"] == "pve5"


def test_expected_lxc_stopped_with_onboot_is_warn():
    m = ev(doc(replace(healthy_guests(), 105, status="stopped")))
    assert m["guests"]["105"]["state"] == "STOPPED"
    assert m["verdict"] == "WARN" and m["reason"] == "EXPECTED_GUEST_STOPPED"


def test_paused_vm_is_paused_not_running_and_warns():
    m = ev(doc(replace(healthy_guests(), 110, status="running", qmpstatus="paused")))
    assert m["guests"]["110"]["state"] == "PAUSED"
    assert m["guests"]["110"]["raw_status"] == "running"    # what `qm list` would have shown
    assert m["verdict"] == "WARN" and m["reason"] == "EXPECTED_GUEST_PAUSED"


def test_paused_mapping_covers_suspended_and_prelaunch_only():
    for qmp in ("suspended", "prelaunch"):
        assert GS.guest_state(g(1, "qemu", "x", qmp=qmp)) == "PAUSED", qmp
    for qmp in ("io-error", "guest-panicked", "inmigrate", None, ""):
        assert GS.guest_state({**g(1, "qemu", "x"), "qmpstatus": qmp}) == "UNKNOWN", qmp
    assert GS.guest_state(g(1, "qemu", "x", status="stopped", qmp="stopped")) == "STOPPED"
    assert GS.guest_state(g(1, "lxc", "x", status="weird")) == "UNKNOWN"


def test_missing_guest_is_missing_not_stopped_and_warns():
    m = ev(doc([x for x in healthy_guests() if x["vmid"] != 112]))
    assert m["guests"]["112"]["state"] == "MISSING"
    assert m["missing"] == [112] and m["counts"]["STOPPED"] == 0
    assert m["verdict"] == "WARN" and m["reason"] == "EXPECTED_GUEST_MISSING"


def test_pve5_unreachable_is_unreachable_never_zero_healthy():
    out = "ssh: connect to host 192.168.10.203 port 22: No route to host"
    assert mon.classify("guest_state", 255, out, now=NOW, host="pve5") == "UNREACHABLE"
    m = ev(out, rc=255)
    assert m["collection"] == "COLLECTION_FAILED" and m["collection_error"] == "NONZERO_EXIT"
    assert m["counts"]["RUNNING"] == 0 and m["counts"]["MISSING"] == 0
    assert m["counts"]["UNKNOWN"] == 4 and m["missing"] == []
    assert m["verdict"] == "UNKNOWN"


def test_auth_failure_keeps_the_generic_verdict():
    assert mon.classify("guest_state", 1, "sudo: a password is required", host="pve5") == "AUTH-FAIL"


def test_wrapper_pvesh_timeout_is_unknown():
    out = doc(guests=[], ok=False, error="PVESH_TIMEOUT")
    m = ev(out, rc=1)
    assert m["verdict"] == "UNKNOWN" and m["collection"] == "COLLECTION_FAILED"
    assert m["collection_error"] == "PVESH_TIMEOUT" and m["missing"] == []
    assert mon.classify("guest_state", 1, out, now=NOW, host="pve5") == "UNKNOWN"


def test_monitor_level_timeout_is_timeout_never_ok():
    assert mon.classify("guest_state", 124, "<timeout after 120s>", host="pve5") == "TIMEOUT"
    m = ev("<timeout after 120s>", rc=124)
    assert m["collection"] == "COLLECTION_FAILED" and m["verdict"] == "UNKNOWN"


def test_malformed_output_is_unknown():
    cases = ["{not json", "", "[]", '"text"',
             json.dumps({"schema": GS.SCHEMA, "node": "pve5", "collected_at": NOW, "ok": True,
                         "error": None, "guests": [{"vmid": "105", "type": "lxc", "name": "a",
                                                    "status": "running"}]}),
             json.dumps({"schema": GS.SCHEMA, "node": "pve5", "collected_at": NOW, "ok": True,
                         "error": None, "guests": "nope"}),
             doc(healthy_guests() + [g(105, "lxc", "dup")]),
             doc(collected_at=None),
             doc(collected_at="yesterday")]
    for out in cases:
        m = ev(out)
        assert m["verdict"] == "UNKNOWN", out
        assert m["collection"] == "COLLECTION_FAILED", out
        assert m["missing"] == [] and m["counts"]["RUNNING"] == 0, out


def test_wrong_schema_or_wrong_node_is_collection_failed():
    for out, err in ((doc(schema="netframe-guest-state/v0"), "WRONG_SCHEMA"),
                     (doc(node="pve4"), "WRONG_NODE")):
        m = ev(out)
        assert m["collection"] == "COLLECTION_FAILED" and m["collection_error"] == err
        assert m["verdict"] == "UNKNOWN"
    # Without a host the node cannot be confirmed: never OK.
    assert ev(doc(), host=None)["verdict"] == "UNKNOWN"


def test_ok_document_with_nonzero_exit_is_not_trusted():
    m = ev(doc(), rc=1)
    assert m["collection"] == "COLLECTION_FAILED" and m["verdict"] == "UNKNOWN"


def test_stale_or_future_collected_at_is_unknown():
    for ts in (NOW - GS.MAX_AGE_S - 1, NOW - 86400, NOW + GS.CLOCK_SLACK_S + 1):
        m = ev(doc(collected_at=ts))
        assert m["collection"] == "STALE" and m["verdict"] == "UNKNOWN" and m["reason"] == "STALE", ts
        assert m["counts"]["RUNNING"] == 0 and m["missing"] == []
    assert ev(doc(collected_at=NOW - GS.MAX_AGE_S))["verdict"] == "OK"
    assert ev(doc(collected_at=NOW + 60))["verdict"] == "OK"     # modest skew is tolerated


def test_max_age_is_derived_from_the_check_timeout():
    assert GS.CHECK_TIMEOUT_S == mon.CHECK_TIMEOUT
    assert GS.MAX_AGE_S == mon.CHECK_TIMEOUT + GS.CLOCK_SLACK_S
    assert GS.CLOCK_SLACK_S == mon.JOURNAL_CLOCK_SLACK_S


def test_extra_unknown_guest_is_visible_and_verdict_unchanged():
    m = ev(doc(healthy_guests() + [g(999, "lxc", "surprise", status="stopped", onboot=0)]))
    assert m["extra"] == [{"vmid": 999, "name": "surprise", "type": "lxc", "state": "STOPPED"}]
    assert m["guests"]["999"]["expected"] is False
    assert m["verdict"] == "OK"


def test_rename_with_same_vmid_is_visible_identity_kept():
    m = ev(doc(replace(healthy_guests(), 105, name="headscale-new")))
    assert m["renamed"] == [{"vmid": 105, "expected_name": "headscale",
                             "observed_name": "headscale-new"}]
    assert m["guests"]["105"]["expected"] is True and m["guests"]["105"]["state"] == "RUNNING"
    assert m["missing"] == [] and m["extra"] == []
    assert m["verdict"] == "OK"


def test_type_change_with_same_vmid_is_visible():
    m = ev(doc(replace(healthy_guests(), 112, type="qemu", qmpstatus="running")))
    assert m["retyped"] == [{"vmid": 112, "expected_type": "lxc", "observed_type": "qemu"}]


def test_mixed_lxc_and_vm_states():
    guests = replace(replace(healthy_guests(), 110, qmpstatus="paused"), 108, status="stopped")
    m = ev(doc(guests))
    assert {k: v["type"] for k, v in m["guests"].items()} == {
        "105": "lxc", "108": "lxc", "110": "qemu", "112": "lxc"}
    assert m["counts"] == {"RUNNING": 2, "STOPPED": 1, "PAUSED": 1, "MISSING": 0, "UNKNOWN": 0}
    assert m["verdict"] == "WARN"


def test_zero_guests_unexpectedly_is_unknown_never_all_missing():
    m = ev(doc(guests=[]))
    assert m["collection"] == "ZERO_UNEXPECTED" and m["verdict"] == "UNKNOWN"
    assert m["reason"] == "ZERO_UNEXPECTED"
    assert m["missing"] == [] and m["counts"]["MISSING"] == 0 and m["counts"]["UNKNOWN"] == 4


def test_onboot_zero_stopped_guest_is_not_warn():
    m = ev(doc(replace(healthy_guests(), 112, status="stopped", onboot=0)))
    assert m["guests"]["112"]["state"] == "STOPPED" and m["guests"]["112"]["onboot"] == 0
    assert m["verdict"] == "OK"


def test_unmeasured_onboot_on_a_stopped_guest_is_unknown_not_guessed():
    m = ev(doc(replace(healthy_guests(), 112, status="stopped", onboot=None)))
    assert m["verdict"] == "UNKNOWN" and m["reason"] == "ONBOOT_UNMEASURED"


def test_measured_fault_outranks_an_unknown_guest():
    guests = replace(replace(healthy_guests(), 110, qmpstatus="io-error"), 105, status="stopped")
    m = ev(doc(guests))
    assert m["guests"]["110"]["state"] == "UNKNOWN"
    assert m["verdict"] == "WARN" and m["reason"] == "EXPECTED_GUEST_STOPPED"
    m = ev(doc(replace(healthy_guests(), 110, qmpstatus="io-error")))
    assert m["verdict"] == "UNKNOWN" and m["reason"] == "GUEST_STATE_UNKNOWN"


def test_reasons_are_bounded_vocabulary():
    for r in GS.REASONS:
        assert mon.check_reason("guest_state", {"reason": r}) == r


def test_verdict_and_metrics_agree_through_the_monitor():
    mon._GUEST_CACHE.clear()
    mon._GUEST_CACHE["inventory"] = INV
    for out in (doc(), doc(replace(healthy_guests(), 105, status="stopped")), "{bad", doc(guests=[])):
        assert mon.classify("guest_state", 0, out, now=NOW, host="pve5") == \
            mon.parse_guest_state(out, rc=0, now=NOW, host="pve5")["verdict"]


# --- dashboard safety and scope ---------------------------------------------------------------
def test_pve5_never_emits_the_legacy_guests_check():
    checks = mon.NODES["pve5"]["checks"]
    assert "guests" not in checks
    assert checks["guest_state"] == "sudo -n /usr/local/sbin/nfm-guests"
    # The older nodes keep their behaviour unchanged.
    assert mon.NODES["pve3"]["checks"]["guests"] == mon.PCT_LIST
    assert mon.NODES["pve4"]["checks"]["guests"] == mon.PCT_LIST
    assert mon.NODES["quarkylab"]["checks"]["guests"] == mon.QM_LIST
    assert all("guest_state" not in c["checks"] for h, c in mon.NODES.items() if h != "pve5")


def test_running_guest_never_yields_an_application_field():
    m = ev(doc())
    banned = ("up", "healthy", "health", "service", "services", "app", "application",
              "nominal", "functionally_verified", "auth_enforced")

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                assert str(k).lower() not in banned, k
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
    walk(m)
    assert "not application health" in m["semantics"]
    # No guest maps to a bare status string, which is the shape the wall paints green.
    assert all(isinstance(v, dict) for v in m["guests"].values())
    flat = mon.flatten_metrics({"pve5": {"guest_state": {"verdict": "OK", "metrics": m}}})
    assert not any(k.endswith(".up") or k.endswith(".verified") for k in flat)


def test_flat_export_counts_only_trusted_collections():
    ok = mon.flatten_metrics({"pve5": {"guest_state": {"metrics": ev(doc())}}})
    assert ok["pve5.guest_state.collection_ok"] == 1 and ok["pve5.guest_state.running"] == 4
    assert ok["pve5.guest_state.missing"] == 0 and ok["pve5.guest_state.extra"] == 0
    bad = mon.flatten_metrics({"pve5": {"guest_state": {"metrics": ev("{bad")}}})
    assert bad == {"pve5.guest_state.collection_ok": 0}


def test_textfile_export_carries_a_bounded_reason():
    m = ev(doc(replace(healthy_guests(), 105, status="stopped")))
    text = mon.render_metrics({"nodes": {"pve5": {"guest_state": {"verdict": "WARN", "metrics": m}}}},
                              now=NOW)
    assert ('netframe_monitor_check_status{node="pve5",check="guest_state",state="warn",'
            'reason="EXPECTED_GUEST_STOPPED"} 1') in text
    assert "headscale" not in text                      # no guest name ever becomes a label


# --- the real main() over several nodes -------------------------------------------------------
def _drive_main(monkeypatch, tmp_path, node_outputs):
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
    mon._GUEST_CACHE.clear()
    mon._GUEST_CACHE["inventory"] = INV
    rc = mon.main()
    return rc, json.load(open(tmp_path / "last_run.json")), history


PCT_OK = "VMID       Status     Lock         Name\n101        running                 grafana\n"


def test_pve5_failure_does_not_alter_other_nodes(monkeypatch, tmp_path):
    others = [("pve3", "df", 0, "/dev/sda1 100G 10G 90G 10% /"),
              ("pve3", "guests", 0, PCT_OK),
              ("pve4", "guests", 0, PCT_OK)]
    rc_ok, rep_ok, _ = _drive_main(monkeypatch, tmp_path, others + [
        ("pve5", "guest_state", 0, doc(collected_at=int(time.time())))])
    rc_bad, rep_bad, hist = _drive_main(monkeypatch, tmp_path, others + [
        ("pve5", "guest_state", 255, "ssh: connect to host 192.168.10.203 port 22: No route to host")])
    for host in ("pve3", "pve4"):
        for name, c in rep_ok["nodes"][host].items():
            assert rep_bad["nodes"][host][name]["verdict"] == c["verdict"] == "OK"
            assert rep_bad["nodes"][host][name]["metrics"] == c["metrics"]
    assert rep_ok["nodes"]["pve5"]["guest_state"]["verdict"] == "OK" and rc_ok == 0
    bad = rep_bad["nodes"]["pve5"]["guest_state"]
    assert bad["verdict"] == "UNREACHABLE" and bad["metrics"]["collection"] == "COLLECTION_FAILED"
    assert rc_bad == 1 and rep_bad["worst"] == "UNREACHABLE"
    assert "guests" not in rep_bad["nodes"]["pve5"] and "guests" not in rep_ok["nodes"]["pve5"]
    assert hist[0]["metrics"]["pve5.guest_state.collection_ok"] == 0
    assert "pve5.guest_state.running" not in hist[0]["metrics"]


def test_main_records_a_wrapper_failure_as_unknown(monkeypatch, tmp_path):
    rc, rep, hist = _drive_main(monkeypatch, tmp_path, [
        ("pve5", "guest_state", 1, doc(guests=[], ok=False, error="PVESH_NOT_JSON"))])
    c = rep["nodes"]["pve5"]["guest_state"]
    assert c["verdict"] == "UNKNOWN" and c["metrics"]["collection_error"] == "PVESH_NOT_JSON"
    assert rc == 0 and rep["worst"] == "UNKNOWN"         # measured-unknown, not a blind ssh path
    assert hist[0]["verdicts"]["pve5.guest_state"] == "UNKNOWN"


# --- the wrapper, executed against a stub pvesh and a fake /etc/pve ----------------------------
WRAPPER = os.path.join(BASE, "node-local", "pve-nfm-guests")


def _wrapper():
    loader = importlib.machinery.SourceFileLoader("pve_nfm_guests", WRAPPER)
    spec = importlib.util.spec_from_loader("pve_nfm_guests", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


LXC_JSON = [{"vmid": 105, "name": "headscale", "status": "running"},
            {"vmid": 108, "name": "netframe-pihole2", "status": "running", "lock": "backup"},
            {"vmid": 112, "name": "minecraft", "status": "stopped"}]
QEMU_JSON = [{"vmid": 110, "name": "homeassistant", "status": "running", "qmpstatus": "paused"}]


def _fake_host(tmp_path, monkeypatch, lxc=None, qemu=None, mode="ok", node="pve5"):
    """A stub `pvesh` on a private PATH plus a fake /etc/pve. Returns (wrapper module, calls log)."""
    wr = _wrapper()
    bindir, pve = tmp_path / "bin", tmp_path / "pve"
    bindir.mkdir()
    (bindir / "lxc.json").write_text(json.dumps(LXC_JSON if lxc is None else lxc))
    (bindir / "qemu.json").write_text(json.dumps(QEMU_JSON if qemu is None else qemu))
    calls = tmp_path / "calls.log"
    stub = bindir / "pvesh"
    stub.write_text(f"""#!/usr/bin/python3
import sys, time
open({str(calls)!r}, "a").write(" ".join(sys.argv[1:]) + "\\n")
mode = {mode!r}
if mode == "fail":
    sys.stderr.write("ipcc_send_rec failed: secret detail\\n"); sys.exit(255)
if mode == "timeout":
    time.sleep(10)
if mode == "notjson":
    print("Use of uninitialized value"); sys.exit(0)
kind = "qemu" if sys.argv[2].endswith("/qemu") else "lxc"
sys.stdout.write(open({str(bindir)!r} + "/" + kind + ".json").read())
""")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    for sub, vmid, text in (("lxc", 105, "arch: amd64\nonboot: 1\nhostname: headscale\n"),
                            ("lxc", 108, "onboot: 1\n"),
                            # onboot only inside a snapshot section: the live config says default 0
                            ("lxc", 112, "hostname: minecraft\n\n[before-upgrade]\nonboot: 1\n"),
                            ("qemu-server", 110, "onboot: 1\nagent: 1\n")):
        d = pve / "nodes" / node / sub
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{vmid}.conf").write_text(text)
    monkeypatch.setattr(wr, "SAFE_PATH", str(bindir))
    monkeypatch.setattr(wr, "PVE_ROOT", str(pve))
    monkeypatch.setattr(wr, "short_hostname", lambda: node)
    monkeypatch.setattr(wr, "TIMEOUT", 1)
    return wr, calls


def _run(wr, capsys, argv=("nfm-guests",)):
    rc = wr.main(list(argv))
    out = capsys.readouterr().out
    assert len(out.strip().splitlines()) == 1, "exactly one JSON document"
    return rc, json.loads(out)


def test_wrapper_success(tmp_path, monkeypatch, capsys):
    wr, calls = _fake_host(tmp_path, monkeypatch)
    rc, d = _run(wr, capsys)
    assert rc == 0 and d["ok"] is True and d["error"] is None
    assert d["schema"] == GS.SCHEMA and d["node"] == "pve5" and isinstance(d["collected_at"], int)
    by = {x["vmid"]: x for x in d["guests"]}
    assert [x["vmid"] for x in d["guests"]] == [105, 108, 110, 112]
    assert by[110] == {"vmid": 110, "type": "qemu", "name": "homeassistant", "status": "running",
                       "qmpstatus": "paused", "lock": None, "onboot": 1}
    assert by[108]["lock"] == "backup" and by[108]["qmpstatus"] is None
    assert by[112]["onboot"] == 0                       # snapshot section ignored
    # read-only: only the two fixed GETs, qemu with --full so qmpstatus is present
    assert calls.read_text().splitlines() == [
        "get /nodes/pve5/lxc --output-format json",
        "get /nodes/pve5/qemu --output-format json --full 1"]
    # and the monitor classifies the real wrapper output end to end
    m = GS.evaluate(json.dumps(d), rc=rc, host="pve5", now=d["collected_at"], inventory=INV)
    assert m["guests"]["110"]["state"] == "PAUSED" and m["guests"]["112"]["state"] == "STOPPED"
    assert m["verdict"] == "WARN" and m["reason"] == "EXPECTED_GUEST_PAUSED"


def test_wrapper_unreadable_config_is_null_onboot(tmp_path, monkeypatch, capsys):
    wr, _ = _fake_host(tmp_path, monkeypatch)
    os.remove(tmp_path / "pve" / "nodes" / "pve5" / "lxc" / "105.conf")
    rc, d = _run(wr, capsys)
    assert rc == 0 and {x["vmid"]: x["onboot"] for x in d["guests"]}[105] is None


def test_wrapper_pvesh_failure(tmp_path, monkeypatch, capsys):
    wr, _ = _fake_host(tmp_path, monkeypatch, mode="fail")
    rc, d = _run(wr, capsys)
    assert rc != 0 and d["ok"] is False and d["error"] == "PVESH_FAILED" and d["guests"] == []
    assert "secret" not in json.dumps(d)                # stderr never leaves the host


def test_wrapper_timeout(tmp_path, monkeypatch, capsys):
    wr, _ = _fake_host(tmp_path, monkeypatch, mode="timeout")
    rc, d = _run(wr, capsys)
    assert rc != 0 and d["ok"] is False and d["error"] == "PVESH_TIMEOUT" and d["guests"] == []


def test_wrapper_non_json(tmp_path, monkeypatch, capsys):
    wr, _ = _fake_host(tmp_path, monkeypatch, mode="notjson")
    rc, d = _run(wr, capsys)
    assert rc != 0 and d["ok"] is False and d["error"] == "PVESH_NOT_JSON" and d["guests"] == []


def test_wrapper_malformed_entry_fails_whole_collection(tmp_path, monkeypatch, capsys):
    wr, _ = _fake_host(tmp_path, monkeypatch, qemu=[{"vmid": "../../etc", "status": "running"}])
    rc, d = _run(wr, capsys)
    assert rc != 0 and d["error"] == "PVESH_MALFORMED" and d["guests"] == []


def test_wrapper_missing_pvesh(tmp_path, monkeypatch, capsys):
    wr, _ = _fake_host(tmp_path, monkeypatch)
    os.remove(tmp_path / "bin" / "pvesh")
    rc, d = _run(wr, capsys)
    assert rc != 0 and d["error"] == "PVESH_UNAVAILABLE"


def test_wrapper_refuses_arguments(tmp_path, monkeypatch, capsys):
    wr, calls = _fake_host(tmp_path, monkeypatch)
    rc, d = _run(wr, capsys, ("nfm-guests", "--node", "pve3"))
    assert rc == 2 and d["error"] == "ARGS_REFUSED" and d["ok"] is False
    assert not calls.exists(), "nothing may run when arguments are given"


def test_wrapper_guest_name_with_shell_metacharacters_is_data(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)                          # a relative `touch` would land here
    marker = tmp_path / "PWNED"
    evil = "x$(touch PWNED);`touch PWNED`;rm -rf /tmp/nothing|&>'\"\n../../etc/passwd"
    wr, _ = _fake_host(tmp_path, monkeypatch,
                       lxc=[{"vmid": 105, "name": evil, "status": "running"}], qemu=[])
    rc, d = _run(wr, capsys)
    assert rc == 0 and d["guests"][0]["name"] == evil and d["guests"][0]["onboot"] == 1
    assert not marker.exists(), "a guest name was executed"
    m = GS.evaluate(json.dumps(d), rc=0, host="pve5", now=d["collected_at"], inventory=INV)
    assert m["renamed"] == [{"vmid": 105, "expected_name": "headscale", "observed_name": evil}]
    assert not marker.exists()


def test_wrapper_source_is_shell_free_and_bounded():
    src = open(WRAPPER).read()
    assert "shell=True" not in src and "os.system" not in src and "os.popen" not in src
    assert "timeout=TIMEOUT" in src
    assert os.access(WRAPPER, os.X_OK), "the wrapper must be committed executable"


def test_sudoers_source_pins_no_arguments():
    text = open(os.path.join(BASE, "node-local", "pve5-nfm-guests.sudoers")).read()
    rules = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    assert rules == ['monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-guests ""']
