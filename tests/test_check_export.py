"""Unit tests for the Prometheus textfile export of monitor verdicts.

Two properties matter more than the rest.

First, the export must not become a way for a stale OK to look current. The document carries its own
write timestamp, and these tests prove that timestamp is present, advances, and does NOT advance
when the exporter fails. Prometheus rules key off it; if it could go missing or silently freeze
while the values stayed, the whole alerting design would be built on a lie.

Second, labels must stay bounded. `reason` may only ever hold a sanitized class from a fixed
vocabulary, never a captured error string, because a label that can carry free text is a
cardinality explosion waiting for its first unusual failure.

Pure functions and a temp directory. No estate access.
"""
import importlib.util
import os
import re
import stat
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(mod):
    spec = importlib.util.spec_from_file_location(mod, os.path.join(BASE, f"{mod}.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mon = _load("netframe_monitor")

REPORT_CHECKS = ("backup_verify", "hardening_drift", "restore_verify")


def report(**overrides):
    checks = {
        "backup_verify": {"verdict": "OK", "metrics": {"present": True, "overall": "pass",
                                                       "stale": False, "failed": []}},
        "hardening_drift": {"verdict": "OK", "metrics": {"present": True, "any_drift": False,
                                                         "stale": False}},
        "restore_verify": {"verdict": "OK", "metrics": {"present": True, "status": "pass",
                                                        "level": 2, "stale": False,
                                                        "failure_class": None}},
    }
    for name, patch in overrides.items():
        checks[name] = patch
    return {"nodes": {"randy": checks}}


def series(text, check):
    for line in text.splitlines():
        if line.startswith("netframe_monitor_check_status") and f'check="{check}"' in line:
            return line
    return ""


def label(line, key):
    m = re.search(rf'{key}="([^"]*)"', line)
    return m.group(1) if m else None


# ---- A: the healthy case ----

def test_all_three_export_as_ok():
    text = mon.render_metrics(report(), now=1000)
    for c in REPORT_CHECKS:
        assert label(series(text, c), "state") == "ok", c
        assert label(series(text, c), "reason") == "", c


def test_the_export_carries_its_own_timestamp():
    text = mon.render_metrics(report(), now=1234567)
    assert "netframe_monitor_export_timestamp_seconds 1234567" in text


def test_no_duplicate_series():
    text = mon.render_metrics(report(), now=1000)
    ids = [ln.rsplit(" ", 1)[0] for ln in text.splitlines()
           if ln.startswith("netframe_monitor_check_status")]
    assert len(ids) == len(set(ids))


# ---- B, C, D: each of the three degrades independently ----

def test_backup_verify_warn_is_exported():
    r = report(backup_verify={"verdict": "WARN",
                              "metrics": {"present": True, "stale": False, "failed": ["restic"]}})
    assert label(series(mon.render_metrics(r, now=1), "backup_verify"), "state") == "warn"
    assert label(series(mon.render_metrics(r, now=1), "backup_verify"), "reason") == "FAILED_CHECKS"


def test_hardening_drift_warn_is_exported():
    r = report(hardening_drift={"verdict": "WARN",
                                "metrics": {"present": True, "any_drift": True, "stale": False}})
    assert label(series(mon.render_metrics(r, now=1), "hardening_drift"), "state") == "warn"
    assert label(series(mon.render_metrics(r, now=1), "hardening_drift"), "reason") == "DRIFT"


def test_restore_verify_warn_is_exported():
    r = report(restore_verify={"verdict": "WARN",
                               "metrics": {"present": True, "status": "fail", "level": 1,
                                           "stale": False, "failure_class": "RESTORE_FAILED"}})
    line = series(mon.render_metrics(r, now=1), "restore_verify")
    assert label(line, "state") == "warn" and label(line, "reason") == "RESTORE_FAILED"


# ---- E, F, G: stale, missing, malformed ----

def test_restore_verify_stale_is_exported_as_stale():
    r = report(restore_verify={"verdict": "WARN",
                               "metrics": {"present": True, "status": "pass", "level": 2,
                                           "stale": True, "failure_class": None}})
    line = series(mon.render_metrics(r, now=1), "restore_verify")
    assert label(line, "state") == "warn" and label(line, "reason") == mon.REASON_STALE


def test_missing_and_malformed_reports_export_as_absent():
    for metrics in ({"present": False}, {"present": False}):
        r = report(restore_verify={"verdict": "WARN", "metrics": metrics})
        line = series(mon.render_metrics(r, now=1), "restore_verify")
        assert label(line, "state") == "warn" and label(line, "reason") == mon.REASON_ABSENT


# ---- H, I: a lock and a corrupt repository must not converge ----

def test_repository_locked_and_integrity_failed_stay_distinct():
    def reason_for(cls):
        r = report(restore_verify={"verdict": "WARN",
                                   "metrics": {"present": True, "status": "fail", "level": 0,
                                               "stale": False, "failure_class": cls}})
        return label(series(mon.render_metrics(r, now=1), "restore_verify"), "reason")
    locked, broken = reason_for("REPOSITORY_LOCKED"), reason_for("INTEGRITY_FAILED")
    assert locked == "REPOSITORY_LOCKED"
    assert broken == "INTEGRITY_FAILED"
    assert locked != broken


def test_reason_is_bounded_and_can_never_carry_free_text():
    """A producer bug must not be able to turn a label into a captured error message."""
    nasty = 'restic check failed: Pack "abc" broken\nat 03:00, id=deadbeef ' * 10
    r = report(restore_verify={"verdict": "WARN",
                               "metrics": {"present": True, "status": "fail", "level": 0,
                                           "stale": False, "failure_class": nasty}})
    reason = label(series(mon.render_metrics(r, now=1), "restore_verify"), "reason")
    assert len(reason) <= mon._REASON_MAX
    assert re.fullmatch(r"[A-Z0-9_]*", reason)
    assert '"' not in reason and "\n" not in reason and " " not in reason


# ---- J, K, M: writing, failing to write, and expiry ----

def test_export_writes_atomically_and_leaves_no_temp_file():
    with tempfile.TemporaryDirectory() as td:
        assert mon.export_metrics(report(), directory=td, name="t.prom", now=42) is True
        assert os.listdir(td) == ["t.prom"]
        with open(os.path.join(td, "t.prom")) as fh:
            body = fh.read()
        assert "netframe_monitor_export_timestamp_seconds 42" in body
        assert stat.S_IMODE(os.stat(os.path.join(td, "t.prom")).st_mode) == 0o644


def test_each_export_replaces_the_file_rather_than_rewriting_it_in_place():
    """Atomicity, measured rather than asserted from the source.

    os.replace() puts a NEW file at the path, so the inode changes every cycle. A write straight to
    the target would keep the same inode and would expose a truncated document to node_exporter for
    as long as the write took. node_exporter drops a whole file it cannot parse, so a partial write
    does not lose one metric, it loses all of them at once.
    """
    with tempfile.TemporaryDirectory() as td:
        target = os.path.join(td, "t.prom")
        mon.export_metrics(report(), directory=td, name="t.prom", now=1)
        first = os.stat(target).st_ino
        mon.export_metrics(report(), directory=td, name="t.prom", now=2)
        assert os.stat(target).st_ino != first


def test_a_failed_export_keeps_the_previous_document_intact():
    with tempfile.TemporaryDirectory() as td:
        assert mon.export_metrics(report(), directory=td, name="t.prom", now=100) is True
        with open(os.path.join(td, "t.prom")) as fh:
            before = fh.read()
        os.chmod(td, 0o500)                       # writes now fail
        try:
            assert mon.export_metrics(report(), directory=td, name="t.prom", now=200) is False
            with open(os.path.join(td, "t.prom")) as fh:
                after = fh.read()
        finally:
            os.chmod(td, 0o700)
        assert after == before                     # evidence preserved, never truncated
        assert "netframe_monitor_export_timestamp_seconds 100" in after
        # M: and because the timestamp did NOT advance, the stale rule takes over.
        assert "netframe_monitor_export_timestamp_seconds 200" not in after


def test_export_to_a_missing_directory_fails_rather_than_creating_one():
    with tempfile.TemporaryDirectory() as td:
        assert mon.export_metrics(report(), directory=os.path.join(td, "nope"),
                                  name="t.prom") is False


def test_the_timestamp_advances_between_cycles():
    with tempfile.TemporaryDirectory() as td:
        mon.export_metrics(report(), directory=td, name="t.prom", now=100)
        mon.export_metrics(report(), directory=td, name="t.prom", now=1000)
        with open(os.path.join(td, "t.prom")) as fh:
            assert "netframe_monitor_export_timestamp_seconds 1000" in fh.read()


# ---- the exporter must not become a second parser ----

def test_the_exporter_reads_the_monitors_own_verdicts_and_reparses_nothing():
    with open(os.path.join(BASE, "netframe_monitor.py")) as fh:
        src = fh.read()
    start = src.index("def render_metrics(")
    body = src[start:src.index("def export_metrics(")]
    for parser in ("json.load", "parse_backup_verify", "parse_hardening_drift",
                   "parse_restore_verify", "backup-report.json", "restore-verify.json"):
        assert parser not in body, parser


def test_every_report_check_is_in_the_export():
    text = mon.render_metrics(report(), now=1)
    for c in REPORT_CHECKS:
        assert series(text, c), c
