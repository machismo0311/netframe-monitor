"""Calibration + behavior tests for evidence scoring (NF-AIOPS-005).

The fixtures in eval/evidence-fixtures.json are frozen ground truth, written before the
module. These assert the module satisfies every fixture's expected band, confidence bound,
and which floors/ceilings must (and must not) fire. If a weight change breaks a fixture,
that is the fixture doing its job.
"""
import importlib.util
import json
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "ev", os.path.join(BASE, "netframe_evidence.py"))
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)

FIXTURES = json.load(open(os.path.join(BASE, "eval", "evidence-fixtures.json")))["fixtures"]
BY_ID = {f["id"]: f for f in FIXTURES}


def _score(fid):
    return ev.score(BY_ID[fid]["descriptor"])


def test_all_fixtures_satisfy_their_expectations():
    problems = []
    for f in FIXTURES:
        a = ev.score(f["descriptor"])
        e = f["expect"]
        fired = set(a["confidence_factors_fired"])
        # evidence band
        if "evidence_band" in e and a["evidence_band"] != e["evidence_band"]:
            problems.append(f"{f['id']}: evidence_band {a['evidence_band']} != {e['evidence_band']}")
        # confidence bounds
        if "confidence_max" in e and a["confidence"] > e["confidence_max"]:
            problems.append(f"{f['id']}: confidence {a['confidence']} > max {e['confidence_max']}")
        if "confidence_min" in e and a["confidence"] < e["confidence_min"]:
            problems.append(f"{f['id']}: confidence {a['confidence']} < min {e['confidence_min']}")
        # required / forbidden factors
        for name in e.get("must_fire", []):
            if name not in fired:
                problems.append(f"{f['id']}: expected factor {name} did not fire (got {sorted(fired)})")
        for name in e.get("must_not_fire", []):
            if name in fired:
                problems.append(f"{f['id']}: forbidden factor {name} fired")
    assert not problems, "\n".join(problems)


def test_two_axes_diverge_on_evt004():
    # The whole design: same incident, evidence HIGH both ways, confidence splits by
    # whether the ACTION is right.
    obs = _score("EVT-004-observation-indexer-down")
    act = _score("EVT-004-action-power-cycle")
    assert obs["evidence_band"] == "HIGH" and act["evidence_band"] == "HIGH"
    assert obs["confidence"] >= 80, "well-evidenced problem should be high-confidence"
    assert act["confidence"] <= 30, "wrong action must be low-confidence despite rich evidence"


def test_low_evidence_high_confidence_is_possible():
    # llm_router: MEDIUM evidence but HIGH confidence, because a bind mismatch is a fact.
    a = _score("llm-router-outage")
    assert a["evidence_band"] in ("MEDIUM", "LOW")
    assert a["confidence"] >= 85
    assert "deterministic_floor" in a["confidence_factors_fired"]


def test_high_evidence_low_confidence_is_possible():
    # conflicting-evidence: HIGH evidence, capped confidence.
    a = _score("conflicting-evidence")
    assert a["evidence_band"] == "HIGH"
    assert a["confidence"] <= 50
    assert "conflict_ceiling" in a["confidence_factors_fired"]


def test_hallucinated_source_contributes_zero():
    a = _score("missing-telemetry-hallucination")
    assert "unverifiable_citation" in {f["factor"] for f in a["evidence_factors"]}
    assert a["evidence_band"] == "LOW"
    assert a["confidence"] <= 30


def test_stale_data_is_capped_and_exposed():
    a = _score("stale-data")
    assert a["freshness"]["stale"] is True
    assert a["confidence"] <= 40
    assert "staleness_ceiling" in a["confidence_factors_fired"]


def test_explanation_is_mandatory_and_nonempty():
    for f in FIXTURES:
        a = ev.score(f["descriptor"])
        assert a["confidence_explanation"].strip(), f"{f['id']}: empty explanation"
        assert a["confidence_steps"], f"{f['id']}: no confidence steps"


def test_every_evidence_factor_carries_provenance():
    for f in FIXTURES:
        a = ev.score(f["descriptor"])
        for fac in a["evidence_factors"]:
            assert fac["provenance"].strip(), f"{f['id']}: factor {fac['factor']} has no provenance"


def test_freshness_is_exposed_as_a_field():
    for f in FIXTURES:
        a = ev.score(f["descriptor"])
        assert "freshness" in a and "stale" in a["freshness"]


def test_render_produces_all_three_lines():
    a = _score("llm-router-outage")
    out = ev.render(a)
    assert "Evidence quality:" in out
    assert "Confidence:" in out
    assert "Evidence freshness:" in out
