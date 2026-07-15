"""Tests for the merge-gate decision core.

The defect this pins: PR #37 merged while its checks reported nothing, because the
old wait-loop treated 'no checks reported' as completion. The state model here has
no path from silence to a merge.
"""
import importlib.util
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "merge_gate", os.path.join(BASE, "tools", "merge_gate.py"))
mg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mg)

REQ = ["Python lint + syntax", "ShellCheck (bash)"]


def _run(name, status="COMPLETED", conclusion="SUCCESS"):
    return {"name": name, "status": status, "conclusion": conclusion}


def test_no_checks_reported_is_unknown_never_pass():
    state, d = mg.decide([], REQ)
    assert state == mg.UNKNOWN
    assert "no checks reported" in d["reason"]


def test_unknown_when_a_required_check_never_appears():
    # One required check reported and green; the other simply absent. Still UNKNOWN:
    # partial silence is silence.
    state, d = mg.decide([_run(REQ[0])], REQ)
    assert state == mg.UNKNOWN
    assert REQ[1] in d["reason"]


def test_pass_requires_every_required_check_green():
    state, _ = mg.decide([_run(REQ[0]), _run(REQ[1])], REQ)
    assert state == mg.PASS


def test_any_required_failure_is_fail():
    state, d = mg.decide([_run(REQ[0]), _run(REQ[1], conclusion="FAILURE")], REQ)
    assert state == mg.FAIL
    assert REQ[1] in d["reason"]


def test_non_required_failure_also_refuses():
    rollup = [_run(REQ[0]), _run(REQ[1]), _run("extra-lint", conclusion="FAILURE")]
    state, d = mg.decide(rollup, REQ)
    assert state == mg.FAIL
    assert "extra-lint" in d["reason"]


def test_in_progress_is_pending_not_pass():
    rollup = [_run(REQ[0]), _run(REQ[1], status="IN_PROGRESS", conclusion="")]
    state, _ = mg.decide(rollup, REQ)
    assert state == mg.PENDING


def test_duplicate_entries_worst_wins():
    # push + pull_request events produce duplicate runs per name. A green duplicate must
    # not mask a red one.
    rollup = [_run(REQ[0]), _run(REQ[0], conclusion="FAILURE"), _run(REQ[1])]
    state, _ = mg.decide(rollup, REQ)
    assert state == mg.FAIL


def test_status_context_shape_supported():
    # Legacy commit statuses use context/state instead of name/conclusion.
    rollup = [{"context": REQ[0], "state": "SUCCESS"},
              {"context": REQ[1], "state": "SUCCESS"}]
    state, _ = mg.decide(rollup, REQ)
    assert state == mg.PASS


def test_neutral_or_unrecognized_conclusion_does_not_pass():
    rollup = [_run(REQ[0]), _run(REQ[1], conclusion="NEUTRAL")]
    state, _ = mg.decide(rollup, REQ)
    assert state == mg.PENDING  # not PASS; waits, and the timeout turns it into FAIL
