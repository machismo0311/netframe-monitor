"""SMART collection behind MegaRAID controllers: wrapper target selection + collector verdicts.

What is defended. Until 2026-10-09 the `smart` check ran `smartctl -H -A /dev/sdX` for every
lsblk disk with no device type. On QuarkyLab (PERC, LSI SAS3008) the SATA drives' SMART RETURN
STATUS failed with DID_BAD_TARGET, smartctl fell back to "PASSED ... based on an Attribute check"
and the collector read OK, so the drives' own self-assessment was never evaluated. On Randy a RAID
virtual drive with no SMART read "SMART Health Status: OK" while its two member disks were never
polled. The invariants here: a fallback is never OK, an unreadable drive is never OK, a drive that
has no SMART is explicit rather than failed, and every physical disk is polled exactly once.

The `*-wrapper*.txt` fixtures are live nfm-smart output captured read-only on 2026-10-09.
"""
import importlib.machinery
import importlib.util
import os

import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(BASE, "tests", "fixtures", "smart")

spec = importlib.util.spec_from_file_location("mon", os.path.join(BASE, "netframe_monitor.py"))
mon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mon)

WRAPPER = os.path.join(BASE, "node-local", "nfm-smart")
_loader = importlib.machinery.SourceFileLoader("nfm_smart", WRAPPER)
_wspec = importlib.util.spec_from_loader("nfm_smart", _loader)
nfm = importlib.util.module_from_spec(_wspec)
_loader.exec_module(nfm)


def fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return f.read()


def verdict(out):
    return mon.classify("smart", 0, out), mon.parse_smart(out)


ATA_PASSED = """=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   005    Pre-fail  Always       -       0
194 Temperature_Celsius     0x0002   171   171   000    Old_age   Always       -       35 (Min/Max 16/49)
197 Current_Pending_Sector  0x0022   100   100   000    Old_age   Always       -       0"""

# Captured on QuarkyLab, plain /dev/sda path (the old collector's path), rc=4.
ATA_STATUS_CMD_FAILED = """=== START OF READ SMART DATA SECTION ===
SMART Status command failed: Input/output error
SMART overall-health self-assessment test result: PASSED
Warning: This result is based on an Attribute check.

ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   005    Pre-fail  Always       -       0
197 Current_Pending_Sector  0x0022   100   100   000    Old_age   Always       -       0"""

ATA_FAILED = """=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: FAILED!
Drive failure expected in less than 24 hours. SAVE ALL DATA.
See vendor-specific Attribute list for failed Attributes.

ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   001   001   005    Pre-fail  Always   FAILING_NOW 2048
197 Current_Pending_Sector  0x0022   100   100   000    Old_age   Always       -       16"""

SCSI_OK = """=== START OF READ SMART DATA SECTION ===
SMART Health Status: OK

Current Drive Temperature:     35 C
Elements in grown defect list: 0"""


def wrap(*blocks, end=True):
    lines = ["nfm-smart v1", f"policy=direct targets={len(blocks)}"]
    for hdr, body, rc in blocks:
        lines.append(f"== {hdr} ==")
        if body:
            lines.append(body)
        if rc is not None:
            lines.append(f"-- rc={rc}")
    if end:
        lines.append("end=1")
    return "\n".join(lines)


# ---- live fixtures -------------------------------------------------------------------------

def test_healthy_megaraid_sata_with_real_self_assessment_is_ok():
    # Randy: SATA disks behind the AVAGO 3108 answer SMART RETURN STATUS on the plain path, the
    # virtual drive sdw is explicit no-SMART, and its member megaraid,28 is polled directly.
    v, m = verdict(fixture("randy-wrapper-excerpt.txt"))
    assert v == "OK" and m["reason"] == ""
    assert m["states"]["/dev/sda"] == "PASSED"
    assert m["states"]["/dev/bus/0:megaraid,28"] == "PASSED"
    assert m["no_smart"] == ["/dev/sdw"] and m["failed"] == []
    assert mon.check_reason("smart", m) == ""


def test_quarkylab_attribute_fallback_is_unknown_not_ok():
    # The controller cannot return SMART RETURN STATUS even on the passthrough path; smartctl
    # still prints PASSED. That PASSED is an attribute check, not the drive's self-assessment.
    v, m = verdict(fixture("quarkylab-wrapper-passthrough.txt"))
    assert v == "UNKNOWN"
    assert m["reason"] == "STATUS_UNSUPPORTED"
    assert len(m["unverified"]) == 6
    assert m["states"]["/dev/sdc"] == m["states"]["/dev/sdh"] == "PASSED"   # SAS drives are fine
    assert mon.check_reason("smart", m) == "STATUS_UNSUPPORTED"


def test_jarvis_declared_usb_module_is_explicit_and_hidden_pd_is_polled():
    v, m = verdict(fixture("jarvis-wrapper.txt"))
    assert m["no_smart"] == ["/dev/sdh"]
    assert m["states"]["/dev/bus/0:megaraid,3"] == "STATUS_UNSUPPORTED"
    assert v == "UNKNOWN" and m["reason"] == "STATUS_UNSUPPORTED"


def test_plain_ahci_node_is_ok():
    v, m = verdict(fixture("pve2-wrapper.txt"))
    assert v == "OK" and m["devices"] == 2 and m["failed"] == []


# ---- synthetic cases ------------------------------------------------------------------------

def test_self_assessment_failed_is_warn_with_reason():
    out = wrap(("/dev/sda dev=/dev/bus/0 type=sat+megaraid,0 kind=megaraid", ATA_FAILED, 24),
               ("/dev/sdb dev=/dev/sdb kind=direct", ATA_PASSED, 0))
    v, m = verdict(out)
    assert v == "WARN" and m["failed"] == ["/dev/sda"]
    assert mon.check_reason("smart", m) == "SELF_ASSESSMENT_FAILED"
    assert m["worst_reallocated"] == 2048 and m["worst_pending_sectors"] == 16


def test_failed_attribute_check_fallback_is_still_a_failure():
    body = ATA_STATUS_CMD_FAILED.replace("test result: PASSED", "test result: FAILED!")
    v, m = verdict(wrap(("/dev/sda dev=/dev/sda kind=direct", body, 12)))
    assert v == "WARN" and m["reason"] == "SELF_ASSESSMENT_FAILED"


def test_scsi_health_not_ok_is_failure():
    body = SCSI_OK.replace("Status: OK", "Status: FAILURE PREDICTION THRESHOLD EXCEEDED [asc=5d]")
    v, _ = verdict(wrap(("/dev/sdc dev=/dev/sdc kind=direct", body, 0)))
    assert v == "WARN"


def test_status_command_failed_fallback_is_unknown():
    v, m = verdict(wrap(("/dev/sda dev=/dev/sda kind=direct", ATA_STATUS_CMD_FAILED, 4)))
    assert v == "UNKNOWN" and m["reason"] == "STATUS_CMD_FAILED"


@pytest.mark.parametrize("rc", [0, 4])
def test_fallback_never_ok_regardless_of_rc(rc):
    v, _ = verdict(wrap(("/dev/sda dev=/dev/sda kind=direct", ATA_STATUS_CMD_FAILED, rc)))
    assert v != "OK"


def test_legacy_loop_output_from_2026_10_08_is_no_longer_ok():
    # The exact shape the old collector produced on QuarkyLab: it was classified OK.
    out = "== /dev/sda ==\n" + ATA_STATUS_CMD_FAILED + "\n== /dev/sdc ==\n" + SCSI_OK
    v, m = verdict(out)
    assert v == "UNKNOWN" and m["reason"] == "STATUS_CMD_FAILED"


def test_legacy_output_even_when_all_passed_is_unknown():
    v, m = verdict("== /dev/sda ==\n" + ATA_PASSED)
    assert v == "UNKNOWN" and m["reason"] == "LEGACY_COLLECTOR"


def test_virtual_drive_without_smart_is_explicit_not_failed():
    out = wrap(("/dev/sdw kind=virtual", "nfm: no SMART (controller virtual drive)", None),
               ("/dev/bus/0:megaraid,28 dev=/dev/bus/0 type=megaraid,28 kind=megaraid-hidden",
                SCSI_OK, 0))
    v, m = verdict(out)
    assert v == "OK" and m["no_smart"] == ["/dev/sdw"] and m["failed"] == []


def test_smartctl_reporting_no_capability_is_no_smart():
    body = "SMART support is:     Unavailable - device lacks SMART capability."
    v, m = verdict(wrap(("/dev/sdw dev=/dev/sdw kind=direct", body, 4)))
    assert m["states"]["/dev/sdw"] == "NO_SMART" and v == "OK"


def test_usb_bridge_with_sat_type_is_ok():
    v, m = verdict(wrap(("/dev/sdh dev=/dev/sdh type=sat kind=usb", ATA_PASSED, 0)))
    assert v == "OK" and m["states"]["/dev/sdh"] == "PASSED"


def test_undeclared_unknown_usb_bridge_is_collection_failure():
    body = ("/dev/sdh: Unknown USB bridge [0x413c:0xa101 (0x000)]\n"
            "Please specify device type with the -d option.")
    v, m = verdict(wrap(("/dev/sdh dev=/dev/sdh type=sat kind=usb", body, 1)))
    assert v == "UNKNOWN" and m["reason"] == "COLLECTION_FAILED"


@pytest.mark.parametrize("out,reason", [
    ("", "NO_DEVICES"),
    ("nfm-smart v1\nerr=SCAN_FAILED", "COLLECTION_FAILED"),
    ("nfm-smart v1\nerr=CONF_INVALID", "COLLECTION_FAILED"),
    (wrap(("/dev/sda dev=/dev/sda kind=direct", ATA_PASSED, 0), end=False), "TRUNCATED"),
    (wrap(("/dev/sda dev=/dev/sda kind=direct", ATA_PASSED, None)), "COLLECTION_FAILED"),
    (wrap(("/dev/sda dev=/dev/sda kind=direct", "", "TIMEOUT")), "COLLECTION_FAILED"),
    (wrap(("/dev/sdq dev=/dev/sdq kind=direct",
           "Smartctl open device: /dev/sdq failed: No such device", 2)), "COLLECTION_FAILED"),
    (wrap(("/dev/sda dev=/dev/sda kind=direct", "=== START OF READ SMART DATA SECTION ===", 0)),
     "NO_VERDICT"),
])
def test_collection_failures_are_unknown(out, reason):
    v, m = verdict(out)
    assert v == "UNKNOWN"
    assert m["reason"] == reason
    assert mon.check_reason("smart", m) == reason


def test_one_unknown_disk_makes_the_check_unknown():
    out = wrap(("/dev/sda dev=/dev/sda kind=direct", ATA_PASSED, 0),
               ("/dev/sdb dev=/dev/sdb kind=direct", ATA_STATUS_CMD_FAILED, 4))
    v, m = verdict(out)
    assert v == "UNKNOWN" and m["unverified"] == ["/dev/sdb"]


def test_failure_outranks_unknown():
    out = wrap(("/dev/sda dev=/dev/sda kind=direct", ATA_FAILED, 8), end=False)
    assert verdict(out)[0] == "WARN"


def test_reasons_fit_the_label_contract():
    for r in mon._SMART_REASON_ORDER + ("LEGACY_COLLECTOR",):
        assert mon.check_reason("smart", {"reason": r}) == r and len(r) <= mon._REASON_MAX


def test_auth_failure_still_wins():
    assert mon.classify("smart", 1, "sudo: a password is required") == "AUTH-FAIL"


def test_collector_command_is_the_pinned_wrapper_with_no_arguments():
    assert mon.SMART == "sudo -n /usr/local/sbin/nfm-smart"
    for host, node in mon.NODES.items():
        if "smart" in node["checks"]:
            assert node["checks"]["smart"] == mon.SMART, host


# ---- wrapper: target selection ---------------------------------------------------------------

CONF_DEFAULT = nfm.parse_conf("")


def disk(name, hctl=None, driver=None, vendor=None, usb_id=None):
    return {"name": name, "hctl": hctl, "driver": driver, "vendor": vendor, "usb_id": usb_id}


QUARKYLAB_DISKS = [disk(f"sd{c}", f"0:0:{i}:0", "megaraid_sas", "HGST" if c in "ch" else "ATA")
                   for i, c in enumerate("abcdefgh")]
QUARKYLAB_PDS = [(0, i) for i in range(8)]


def test_quarkylab_passthrough_targets():
    conf = nfm.parse_conf("MEGARAID_SATA_PATH=passthrough\n")
    t = {x["label"]: x for x in nfm.plan_targets(QUARKYLAB_DISKS, QUARKYLAB_PDS, conf)}
    assert len(t) == 8
    for c, n in zip("abdefg", (0, 1, 3, 4, 5, 6)):
        assert (t[f"/dev/sd{c}"]["dev"], t[f"/dev/sd{c}"]["dtype"]) == \
            ("/dev/bus/0", f"sat+megaraid,{n}")
    for c in "ch":   # SAS drives stay on the plain path, which returns their health status
        assert (t[f"/dev/sd{c}"]["dev"], t[f"/dev/sd{c}"]["dtype"]) == (f"/dev/sd{c}", None)


def test_each_physical_disk_polled_exactly_once():
    # The smartmon duplicate: --scan-open lists /dev/sdX AND /dev/bus/0 megaraid,N for each disk.
    for conf in (CONF_DEFAULT, nfm.parse_conf("MEGARAID_SATA_PATH=passthrough")):
        targets = nfm.plan_targets(QUARKYLAB_DISKS, QUARKYLAB_PDS, conf)
        assert len(targets) == 8
        assert not [x for x in targets if x["kind"] == "megaraid-hidden"]


def test_randy_virtual_drive_and_its_members():
    disks = [disk("sda", "0:0:21:0", "megaraid_sas", "ATA"),
             disk("sde", "0:0:25:0", "megaraid_sas", "TOSHIBA"),
             disk("sdw", "0:2:0:0", "megaraid_sas", "AVAGO"),
             disk("sdx", "1:0:0:0", "mpt2sas", "HGST")]
    pds = [(0, 21), (0, 25), (0, 28), (0, 29)]
    t = {x["label"]: x for x in nfm.plan_targets(disks, pds, CONF_DEFAULT)}
    assert t["/dev/sdw"]["kind"] == "virtual" and t["/dev/sdw"]["dev"] is None
    assert t["/dev/sda"]["dev"] == "/dev/sda"      # 3108 returns status on the plain path
    assert t["/dev/bus/0:megaraid,28"]["dtype"] == "megaraid,28"
    assert t["/dev/bus/0:megaraid,29"]["kind"] == "megaraid-hidden"
    assert "/dev/bus/0:megaraid,21" not in t and "/dev/bus/0:megaraid,25" not in t
    assert t["/dev/sdx"]["kind"] == "direct"


def test_usb_declared_no_smart_vs_undeclared_bridge():
    disks = [disk("sdh", "11:0:0:0", "usb-storage", "DELL", "413c:a101"),
             disk("sdi", "12:0:0:0", "usb-storage", "JMicron", "152d:0578")]
    conf = nfm.parse_conf("NO_SMART_USB=413c:a101\n")
    t = {x["label"]: x for x in nfm.plan_targets(disks, [], conf)}
    assert t["/dev/sdh"]["kind"] == "no-smart" and t["/dev/sdh"]["dev"] is None
    assert (t["/dev/sdi"]["kind"], t["/dev/sdi"]["dtype"]) == ("usb", "sat")


@pytest.mark.parametrize("text", ["MEGARAID_SATA_PATH=sometimes", "NO_SMART_USB=dell",
                                  "SMARTCTL=/tmp/x", "garbage"])
def test_conf_rejects_unknown_keys_and_values(text):
    with pytest.raises(nfm.ConfError):
        nfm.parse_conf(text)


def test_scan_parse():
    text = ("/dev/sda -d scsi # /dev/sda, SCSI device\n"
            "/dev/bus/0 -d megaraid,28 # /dev/bus/0 [megaraid_disk_28], SCSI device\n")
    assert nfm.parse_scan(text) == [(0, 28)]


def test_wrapper_refuses_arguments(monkeypatch, capsys):
    monkeypatch.setattr(nfm.sys, "argv", ["nfm-smart", "-t", "long"])
    assert nfm.main() == 2
    assert capsys.readouterr().out.strip() == "err=USAGE"


def test_wrapper_never_runs_a_self_test_or_setting():
    src = open(WRAPPER).read()
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    for bad in ('"-t"', '"-s"', '"-S"', '"-o"', '"--test', '"--set', '"-X"'):
        assert bad not in code


def test_sudoers_pin_is_argument_free():
    text = open(os.path.join(BASE, "node-local", "nfm-smart.sudoers")).read()
    pins = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert pins == ['monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-smart ""']


@pytest.mark.parametrize("name", ["quarkylab-nfm-smart.conf", "jarvis-nfm-smart.conf"])
def test_tracked_node_policies_parse(name):
    nfm.parse_conf(open(os.path.join(BASE, "node-local", name)).read())
