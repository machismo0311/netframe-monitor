#!/usr/bin/env python3
"""Deterministic evidence-quality and confidence scoring (NF-AIOPS-005).

WHY THIS EXISTS
---------------
The interpreter's Findings contract used to tell the model "Confidence: a percentage or
high/med/low". Confidence was the last place the LLM still graded its own correctness -
the most consequential place, because a confident wrong recommendation is worse than an
unsure one. This module moves quality and confidence to code. The model writes the
recommendation wording; these two numbers and their explanation are computed from
provenance and stapled on afterward. No model is consulted here. Pure stdlib.

TWO AXES, NEVER COLLAPSED (owner-approved)
------------------------------------------
  evidence_quality - "how strong is the information base?"  Additive, banded.
  confidence        - "how likely is THIS action correct?"  Floors and ceilings, so
                      determinism, conflict, and historical corrections dominate mere
                      quantity of evidence.

They are correlated but not the same, and the cases where they diverge are the ones that
matter: high-evidence/low-confidence (data conflicts) and low-evidence/high-confidence (a
deterministic fact settles it). A single number cannot express those rows.

The score attaches to the recommended ACTION, not the observation: "the indexer is down"
can be well-evidenced while "power-cycle the VM" is a wrong fix. Confidence is about the
claim in the descriptor.

Everything the scorer trusts must resolve to real provenance. A cited source absent from
telemetry (resolved=false) contributes zero and is flagged - that is the hallucination and
missing-telemetry guard in one. The default posture is disbelief.

INPUT: a finding descriptor (see eval/evidence-fixtures.json _descriptor_schema).
OUTPUT: {evidence_quality, evidence_band, confidence, confidence_explanation,
         evidence_factors, freshness, provenance}. Every factor carries provenance.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Freshness bound: telemetry older than this cannot yield high confidence. The 15-min
# collector means anything past ~1h is a missed cycle; 2h is unambiguously stale.
FRESHNESS_MAX_S = int(os.environ.get("NETFRAME_EVIDENCE_FRESHNESS_S", "5400"))  # 90 min

LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"


def _band(score):
    return LOW if score < 40 else (MEDIUM if score < 70 else HIGH)


def _resolved_sources(desc):
    return [s for s in desc.get("sources", []) if s.get("resolved")]


def _independent_kinds(sources):
    # Same-kind sources corroborate weakly (one signal counted twice); distinct kinds
    # (smart vs network probe vs ssh vs conformance vs loki) are independent paths.
    return {s.get("kind") for s in sources}


def evidence_quality(desc):
    """0-100 additive, then banded. Returns (score, factors) where each factor carries its
    provenance so the number is never bare."""
    factors = []
    real = _resolved_sources(desc)
    cited = desc.get("sources", [])

    # Independent sources: +20 for the first, +12 per additional DISTINCT kind, cap 45.
    # Distinct kinds (smart vs ssh vs network vs conformance) are independent paths;
    # same-kind sources do not stack (one signal counted twice is not corroboration).
    kinds = _independent_kinds(real)
    if real:
        src_pts = min(45, 20 + 12 * (len(kinds) - 1))
        factors.append(("independent_sources", src_pts,
                        f"{len(real)} resolved source(s) across {len(kinds)} kind(s): "
                        + ", ".join(sorted(s["check"] for s in real))))
    else:
        src_pts = 0
        factors.append(("independent_sources", 0, "no resolved sources"))

    # Unverifiable citations: named but absent from telemetry. Zero contribution + flag.
    unresolved = [s for s in cited if not s.get("resolved")]
    if unresolved:
        factors.append(("unverifiable_citation", 0,
                        "cited but absent from telemetry: "
                        + ", ".join(s.get("check", "?") for s in unresolved)))

    # Time coverage: scaled by how much of the requested window is populated.
    tc = desc.get("time_coverage") or {}
    cov, req = tc.get("covered_days", 0), tc.get("requested_days", 0) or 1
    cov_pts = round(20 * min(1.0, cov / req))
    factors.append(("time_coverage", cov_pts, f"{cov}d of {req}d window populated"))

    # Trend duration: consecutive persisting points; a single blip earns little.
    pts = desc.get("trend_duration_points", 0)
    trend_pts = min(15, 3 * pts)
    factors.append(("trend_duration", trend_pts, f"{pts} consecutive persisting point(s)"))

    # Historical match: the signature matches a known event (either direction is still
    # evidence that we recognise the phenomenon).
    ke = desc.get("known_event")
    if ke:
        factors.append(("historical_match", 15,
                        f"matches {ke['id']} ({ke['direction']} the action)"))
    match_pts = 15 if ke else 0

    # Dependency confirmed: the impact is graph-derived, not asserted.
    dep_pts = 10 if desc.get("dependency_confirmed") else 0
    if dep_pts:
        factors.append(("dependency_confirmed", 10, "impact is graph-derived"))

    # Strong-corroboration bonus: >=2 independent kinds AND a deterministic condition AND
    # all agree. This is the current-state shape (a service is down NOW, confirmed by
    # multiple paths) where long history is not required for the evidence to be strong.
    # It rewards EVT-004-observation / llm_router without inflating single-source findings.
    dc = desc.get("deterministic_condition")
    corrob = 0
    if (len(kinds) >= 2 and dc and dc.get("holds")
            and not any(s.get("agrees") is False for s in real)):
        corrob = 10
        factors.append(("strong_corroboration", 10,
                        f"{len(kinds)} independent kinds agree with a deterministic condition"))

    score = min(100, src_pts + cov_pts + trend_pts + match_pts + dep_pts + corrob)
    return score, factors


def confidence(desc, quality):
    """0-100 with floors and ceilings applied in an order that lets determinism and
    conflict dominate breadth. Returns (score, ordered_explanation)."""
    real = _resolved_sources(desc)
    expl = []

    # 1. Base from evidence quality, capped at 70. Breadth alone is never certainty.
    score = min(70, quality)
    expl.append(("base_from_evidence", score, f"evidence quality {quality} capped at 70"))

    ceilings = []  # (name, cap, why) - the MIN cap wins, applied after floors

    # 2. Deterministic-condition floor: a fact outranks a thin base.
    dc = desc.get("deterministic_condition")
    if dc and dc.get("holds"):
        score = max(score, 85)
        expl.append(("deterministic_floor", 85,
                     f"deterministic condition holds: {dc['name']}"))

    # 3. Agreement: all agree -> +10; any conflict -> hard 50 ceiling.
    disagreeing = [s for s in real if s.get("agrees") is False]
    if real and not disagreeing:
        score = min(100, score + 10)
        expl.append(("sources_agree", 10, f"all {len(real)} source(s) agree"))
    elif disagreeing:
        ceilings.append(("conflict_ceiling", 50,
                         "conflicting sources: "
                         + ", ".join(s["check"] for s in disagreeing)))

    # 4. Known-event direction: supports -> +10; contradicts -> 30 ceiling (near-veto).
    ke = desc.get("known_event")
    if ke and ke["direction"] == "supports":
        score = min(100, score + 10)
        expl.append(("known_event_supports", 10, f"action matches {ke['id']} resolution"))
    elif ke and ke["direction"] == "contradicts":
        ceilings.append(("known_event_contradicts_ceiling", 30,
                         f"action contradicts {ke['id']}'s recorded correct answer"))

    # 5. Single-source (and no deterministic condition) -> 45 ceiling.
    if len(real) <= 1 and not (dc and dc.get("holds")):
        ceilings.append(("single_source_ceiling", 45,
                         "one inference is a hypothesis, not a conclusion"))

    # 6. Staleness: any cited-and-real source past the freshness bound -> 40 ceiling.
    stale = [s for s in real if (s.get("age_s") or 0) > FRESHNESS_MAX_S]
    if stale:
        oldest = max(s.get("age_s", 0) for s in stale)
        ceilings.append(("staleness_ceiling", 40,
                         f"telemetry {round(oldest/3600, 1)}h old (bound {FRESHNESS_MAX_S//60}m)"))

    # 7. Unverifiable citation: the finding leans on a source that is not in telemetry.
    # A recommendation built on invented evidence must be strongly distrusted, on the
    # confidence axis too, not only in the evidence band.
    if any(not s.get("resolved") for s in desc.get("sources", [])):
        ceilings.append(("unverifiable_citation_ceiling", 30,
                         "cites a source absent from telemetry"))

    # Record EVERY applicable ceiling so the operator sees all the reasons confidence is
    # capped, then apply the tightest. Determinism cannot rescue conflicting/stale/invented
    # data - the ceiling wins over the floor.
    if ceilings:
        for cap_name, cap_val, cap_why in sorted(ceilings, key=lambda c: c[1]):
            expl.append((cap_name, cap_val, cap_why))
        binding = min(ceilings, key=lambda c: c[1])[1]
        if score > binding:
            score = binding

    # Note the absence of a deterministic condition explicitly when it mattered.
    if not (dc and dc.get("holds")):
        expl.append(("no_deterministic_condition", 0,
                     "no fact settles this; it rests on inference"))

    return int(round(score)), expl


def freshness(desc):
    """Expose the age of the evidence base as a first-class field (owner requirement)."""
    real = _resolved_sources(desc)
    ages = [s.get("age_s") for s in real if s.get("age_s") is not None]
    if not ages:
        return {"oldest_s": None, "stale": False, "detail": "no aged sources"}
    oldest = max(ages)
    return {"oldest_s": oldest, "stale": oldest > FRESHNESS_MAX_S,
            "detail": f"oldest source {round(oldest/60)}m old"}


def score(desc):
    """The public entry point. Returns the full assessment for one finding descriptor.
    Deterministic; no model. Every factor carries provenance; the explanation is
    mandatory and never empty."""
    q, qfactors = evidence_quality(desc)
    c, cexpl = confidence(desc, q)
    fresh = freshness(desc)
    fired = [name for name, _, _ in cexpl]
    return {
        "claim": desc.get("claim", "?"),
        "evidence_quality": q,
        "evidence_band": _band(q),
        "confidence": c,
        "confidence_explanation": "; ".join(
            f"{name} ({val:+d})" for name, val, _why in cexpl),
        "confidence_factors_fired": fired,
        "evidence_factors": [{"factor": n, "points": p, "provenance": why}
                             for n, p, why in qfactors],
        "confidence_steps": [{"step": n, "value": v, "provenance": why}
                             for n, v, why in cexpl],
        "freshness": fresh,
    }


def render(assessment):
    """Compact operator-facing block for a report. Mandatory explanation included."""
    a = assessment
    lines = [
        f"**Evidence quality:** {a['evidence_band']} ({a['evidence_quality']}/100)",
        f"**Confidence:** {a['confidence']}% - {_explain(a)}",
        f"**Evidence freshness:** {a['freshness']['detail']}"
        + ("  ⚠️ STALE" if a['freshness']['stale'] else ""),
    ]
    return "\n".join(lines)


def _explain(a):
    # Human-readable confidence reason from the ordered steps.
    parts = []
    for s in a["confidence_steps"]:
        if s["step"] in ("base_from_evidence",):
            continue
        parts.append(s["provenance"])
    return "; ".join(parts) if parts else "computed from evidence base"


# --- Building descriptors from real telemetry (the interpreter's entry point) --------
# Deterministic fail predicates: a metric pattern that SETTLES a question without
# inference. Each maps a check to (condition_name, holds?) read only from parsed metrics.
def _deterministic_condition(check, metrics, raw):
    r = str(raw or "")
    if check == "smart" and "self-assessment test result: FAILED" in r:
        return {"name": "smart_overall_health_failed", "holds": True}
    if check == "llm_router_conformance":
        if metrics.get("runtime") == "FAIL":
            return {"name": "runtime_bind_mismatch", "holds": True}
        if metrics.get("firewall") == "FAIL":
            return {"name": "firewall_not_enforcing", "holds": True}
    if check == "wazuh" and metrics.get("core_down"):
        return {"name": "wazuh_core_daemon_down", "holds": True}
    return None


def descriptor_from_finding(host, check, cdata, state, coverage_days, requested_days=14):
    """Build a finding descriptor DETERMINISTICALLY from telemetry for one non-OK check.

    Conservative by design: it asserts only what the telemetry supports and leaves
    everything else null, so the scorer's disbelief-default governs. The claim is the
    OBSERVED finding; where the interpreter later resolves a recommended action, a richer
    descriptor with known_event direction can be supplied. No model involved.
    """
    metrics = cdata.get("metrics", {}) or {}
    raw = cdata.get("raw_excerpt", "")
    # The failing check is one source. A corroborating check on the same host that is also
    # non-OK and of a different kind adds an independent source.
    KIND = {"smart": "smart", "df": "ssh", "zpool": "ssh", "journal_errors": "ssh",
            "gpu": "ssh", "llm_router_conformance": "conformance",
            "llm_router": "network", "wazuh": "ssh", "grafana": "network",
            "loki": "network", "pihole": "network", "backup_verify": "ssh"}
    sources = [{"check": f"{host}.{check}", "kind": KIND.get(check, "ssh"),
                "agrees": True, "value": cdata.get("verdict"),
                "age_s": None, "resolved": True}]
    for other, od in (state.get("nodes", {}).get(host, {}) or {}).items():
        if other != check and od.get("verdict") not in ("OK", None, "SKIPPED"):
            k = KIND.get(other, "ssh")
            if k != KIND.get(check, "ssh"):
                sources.append({"check": f"{host}.{other}", "kind": k, "agrees": True,
                                "value": od.get("verdict"), "age_s": None, "resolved": True})
    dep = False
    try:
        import netframe_knowledge
        dep = bool(netframe_knowledge.impact_for_failures([f"{host}.{check}", host]))
    except Exception:  # noqa: BLE001
        pass
    return {
        "claim": f"{host}.{check} is {cdata.get('verdict', 'non-OK')} (observed finding)",
        "sources": sources,
        "deterministic_condition": _deterministic_condition(check, metrics, raw),
        "time_coverage": {"covered_days": coverage_days, "requested_days": requested_days},
        "trend_duration_points": 0,
        "known_event": None,
        "dependency_confirmed": dep,
        "prior_incident_similarity": None,
    }


# --- The shared report section (NF-AIOPS-005 rollout) --------------------------------
# ONE implementation for every report path. No path calculates its own confidence or
# evidence quality, interprets provenance differently, or renders its own variant: they
# all call section_for_current_state() and get identical semantics. This is the same
# single-engine rule as netframe_policy.enforce().

def coverage_days_from_history(history_path):
    """Days actually spanned by retained history - the honest time-coverage input."""
    try:
        with open(history_path) as fh:
            rows = [line for line in fh if line.strip()]
        if len(rows) < 2:
            return 0
        import json as _json
        from datetime import datetime as _dt
        a = _dt.fromisoformat(_json.loads(rows[0])["ts"])
        b = _dt.fromisoformat(_json.loads(rows[-1])["ts"])
        return round((b - a).total_seconds() / 86400.0, 1)
    except (OSError, ValueError, KeyError):
        return 0


def section_for_state(state, coverage_days, requested_days=14):
    """Deterministic evidence + confidence markdown for each MATERIAL (non-OK) finding
    in `state`. Returns '' when everything is nominal. Annotation only: it never
    suppresses a finding, and low confidence never hides anything - suppression is the
    policy engine's job and only for prohibited actions."""
    findings = []
    for host, checks in (state or {}).get("nodes", {}).items():
        for check, cdata in (checks or {}).items():
            if cdata.get("verdict") in ("OK", None, "SKIPPED"):
                continue
            desc = descriptor_from_finding(host, check, cdata, state,
                                           coverage_days, requested_days)
            findings.append((host, check, score(desc)))
    if not findings:
        return ""
    lines = ["\n\n---\n\n## Evidence & confidence (deterministic, not LLM-generated)\n",
             "_Evidence quality and confidence are computed by code from telemetry "
             "provenance, not stated by the model. Confidence is about the finding, and "
             "it is annotation only - it never suppresses anything._\n"]
    for host, check, a in findings:
        expl = "; ".join(s["provenance"] for s in a["confidence_steps"]
                         if s["step"] != "base_from_evidence") or "computed from evidence"
        lines.append(f"- **{host}.{check}** - evidence **{a['evidence_band']}** "
                     f"({a['evidence_quality']}/100), confidence **{a['confidence']}%**"
                     f"{'  ⚠️ STALE' if a['freshness']['stale'] else ''}  \n"
                     f"  _{expl}_")
    return "\n".join(lines) + "\n"


def section_for_current_state(base=None):
    """One-line entry point for report paths: loads last_run.json + history coverage from
    `base` and returns the section. Never raises - a failed annotation returns '' with a
    stderr warning, because annotation must never break a report."""
    import json as _json
    base = base or os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
    try:
        with open(f"{base}/last_run.json") as fh:
            state = _json.load(fh)
        cov = coverage_days_from_history(f"{base}/history.jsonl")
        return section_for_state(state, cov)
    except Exception as exc:  # noqa: BLE001 - annotation only, never fatal
        print(f"WARN: evidence annotation unavailable ({exc})", file=sys.stderr)
        return ""


def main():
    import json
    if len(sys.argv) > 1:
        desc = json.load(open(sys.argv[1]))
        print(json.dumps(score(desc), indent=2))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
