"""Unit tests for the restore_verify check.

The drill this reads proves a NARROW thing: restic's own integrity check passed, and one file was
extracted from an identified snapshot into a scratch directory. These tests exist mostly to stop
that narrow claim widening into "recovery works", and to stop the two failure modes that a restore
check must never confuse:

  a lock in the way          REPOSITORY_LOCKED   the backups are fine, the drill could not start
  data that does not verify  INTEGRITY_FAILED    the backups are not fine

Conflating those is precisely the defect repaired on 2026-09-02, when a stale lock was logged as
"restic check (repo integrity)" and sat unread for a month because the message implied corruption.

Pure functions over fixture JSON. No host, no repository, no backup touched.

Run: python3 -m pytest tests/ -q
"""
import importlib.util
import json
import os
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(mod):
    spec = importlib.util.spec_from_file_location(mod, os.path.join(BASE, f"{mod}.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


mon = _load("netframe_monitor")

HOURS = 3600


def evidence(status="pass", level=2, level_name="RESTORE_EXTRACTED", failure_class="",
             age_hours=1.0, snapshot="33102858", **extra):
    d = {"schema": "netframe.ares-restore-verify/1", "status": status, "level": level,
         "level_name": level_name, "failure_class": failure_class, "detail": "",
         "snapshot": snapshot, "stale_lock_recovered": False,
         "probe_path": "/home/machismo/.bashrc", "restored_bytes": 3797,
         "restored_sha256": "a" * 64, "matches_live_probe": "identical",
         "repository": "sftp:randy:/mnt/bulk/backups/ares",
         "generated_epoch": int(time.time() - age_hours * HOURS),
         "generated": "2026-09-02T22:03:22-04:00"}
    d.update(extra)
    return json.dumps(d)


# ---- the healthy case, and what it is allowed to claim ----

def test_fresh_level2_pass_is_ok():
    assert mon.classify("restore_verify", 0, evidence()) == "OK"


def test_level_is_preserved_and_stated_literally():
    m = mon.parse_restore_verify(evidence())
    assert m["level"] == 2
    assert m["level_name"] == "RESTORE_EXTRACTED"
    assert m["claim"] == "LEVEL 2 RESTORE_EXTRACTED"
    assert m["snapshot"] == "33102858"


def test_level2_is_never_described_as_boot_or_application_recovery():
    """A file extraction is not a disaster-recovery proof, and must not read like one."""
    m = mon.parse_restore_verify(evidence())
    blob = json.dumps(m).lower()
    for overclaim in ("bootable", "boots", "application_recovery", "application recovery",
                      "disaster recovery", "fully recovered", "restore healthy"):
        assert overclaim not in blob


def test_the_higher_levels_stay_distinct_names():
    assert mon.parse_restore_verify(
        evidence(level=3, level_name="RESTORED_SYSTEM_BOOTABLE"))["level_name"] \
        == "RESTORED_SYSTEM_BOOTABLE"
    assert mon.parse_restore_verify(evidence())["level_name"] == "RESTORE_EXTRACTED"


# ---- staleness derived from the real cadence ----

def test_threshold_covers_the_longest_legitimate_monthly_gap():
    """31-day month plus the timer's 1h jitter, at minimum. A shorter threshold would cry stale
    every long month while the next scheduled run had not yet come round."""
    assert mon.RESTORE_VERIFY_MAX_AGE_H >= 31 * 24 + 1


def test_thirty_day_old_evidence_is_not_stale():
    m = mon.parse_restore_verify(evidence(age_hours=30 * 24))
    assert m["stale"] is False
    assert mon.classify("restore_verify", 0, evidence(age_hours=30 * 24)) == "OK"


def test_evidence_older_than_the_threshold_is_stale_and_warns():
    old = evidence(age_hours=mon.RESTORE_VERIFY_MAX_AGE_H + 1)
    assert mon.parse_restore_verify(old)["stale"] is True
    assert mon.classify("restore_verify", 0, old) == "WARN"


def test_a_definitely_missed_drill_is_stale():
    """Bounds the threshold from ABOVE. Without this, making the threshold enormous would satisfy
    every other staleness test while meaning the check can never report a missed drill."""
    assert mon.parse_restore_verify(evidence(age_hours=90 * 24))["stale"] is True
    assert mon.RESTORE_VERIFY_MAX_AGE_H <= 2 * (31 * 24 + 1)


def test_a_future_timestamp_is_not_treated_as_fresh():
    future = evidence(age_hours=-48)
    m = mon.parse_restore_verify(future)
    assert m["clock_anomaly"] is True and m["stale"] is True
    assert mon.classify("restore_verify", 0, future) == "WARN"


# ---- every failure the drill can report ----

def test_repository_locked_warns_without_implying_corruption():
    out = evidence(status="fail", level=0, level_name="NOTHING_PROVEN",
                   failure_class="REPOSITORY_LOCKED", snapshot="")
    m = mon.parse_restore_verify(out)
    assert mon.classify("restore_verify", 0, out) == "WARN"
    assert m["failure_class"] == "REPOSITORY_LOCKED"
    blob = json.dumps(m).lower()
    assert "corrupt" not in blob and "integrity_failed" not in blob


def test_integrity_failure_is_distinct_from_a_lock():
    locked = mon.parse_restore_verify(
        evidence(status="fail", level=0, failure_class="REPOSITORY_LOCKED"))
    broken = mon.parse_restore_verify(
        evidence(status="fail", level=0, failure_class="INTEGRITY_FAILED"))
    assert locked["failure_class"] != broken["failure_class"]
    assert mon.classify("restore_verify", 0,
                        evidence(status="fail", failure_class="INTEGRITY_FAILED")) == "WARN"


def test_extraction_and_cleanup_failures_warn_with_their_own_class():
    for cls, level in (("RESTORE_FAILED", 1), ("CLEANUP_FAILED", 2), ("TIMEOUT", 0),
                       ("MALFORMED_OUTPUT", 1), ("BACKUP_UNAVAILABLE", 1),
                       ("MISSING_DEPENDENCY", 0)):
        out = evidence(status="fail", level=level, failure_class=cls)
        assert mon.classify("restore_verify", 0, out) == "WARN", cls
        assert mon.parse_restore_verify(out)["failure_class"] == cls


def test_cleanup_failure_at_level_two_still_warns():
    """Extraction genuinely reached LEVEL 2, but the drill failed. The level must not rescue it."""
    out = evidence(status="fail", level=2, failure_class="CLEANUP_FAILED")
    assert mon.classify("restore_verify", 0, out) == "WARN"


def test_a_pass_that_did_not_reach_level_two_warns():
    assert mon.classify("restore_verify", 0,
                        evidence(level=1, level_name="BACKUP_VERIFIED")) == "WARN"


# ---- delivery: absent or unreadable evidence is never success ----

def test_missing_report_is_not_a_successful_drill():
    assert mon.parse_restore_verify("")["present"] is False
    assert mon.classify("restore_verify", 0, "") == "WARN"


def test_malformed_report_is_not_a_successful_drill():
    assert mon.parse_restore_verify("{not json")["present"] is False
    assert mon.classify("restore_verify", 0, "{not json") == "WARN"


def test_no_fixture_short_of_a_fresh_level2_pass_ever_classifies_ok():
    bad = ["", "{not json", "null",
           evidence(status="fail", level=0, failure_class="REPOSITORY_LOCKED"),
           evidence(status="fail", level=0, failure_class="INTEGRITY_FAILED"),
           evidence(status="fail", level=1, failure_class="RESTORE_FAILED"),
           evidence(status="fail", level=2, failure_class="CLEANUP_FAILED"),
           evidence(level=1, level_name="BACKUP_VERIFIED"),
           evidence(age_hours=mon.RESTORE_VERIFY_MAX_AGE_H + 1),
           evidence(age_hours=-48)]
    assert [mon.classify("restore_verify", 0, o) for o in bad] == ["WARN"] * len(bad)


# ---- wiring: the check must actually be collected and parsed ----

def test_restore_verify_is_acquired_from_the_published_randy_copy():
    """It must read what was DELIVERED to Randy, not a producer-local file. Reading the producer's
    own copy would make the check pass while publication was broken, which is the one thing a
    delivery-aware check must not do."""
    assert "restore_verify" in mon.NODES["randy"]["checks"]
    cmd = mon.NODES["randy"]["checks"]["restore_verify"]
    assert "/var/log/netframe-monitor/restore-verify.json" in cmd
    assert ".local/state" not in cmd


def test_restore_verify_has_a_registered_parser():
    assert mon.PARSERS["restore_verify"] is mon.parse_restore_verify


def test_the_acquisition_command_is_unprivileged_and_leaks_nothing():
    cmd = mon.NODES["randy"]["checks"]["restore_verify"]
    assert cmd.startswith("cat ") and "sudo" not in cmd
    assert "password" not in cmd.lower() and "restic" not in cmd.lower()


def test_the_three_facts_stay_separate():
    """Proved / delivered / recent are three fields, not one boolean."""
    m = mon.parse_restore_verify(evidence())
    for field in ("status", "level", "present", "stale", "age_hours", "source"):
        assert field in m
