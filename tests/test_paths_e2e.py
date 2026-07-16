"""End-to-end safety-boundary tests for EVERY LLM-generated operator-visible path.

The question these answer is the one that matters:

    "Can a prohibited operational recommendation reach an operator?"

not "did the model generate one?". The model is stubbed to ALWAYS emit prohibited text,
so these are deterministic and run in CI without Ollama. Each test drives the real main()
of a real path and inspects the artifact an operator would actually read.

A wiring test (`enforce(` appears in the source) proves the call exists. These prove it
works: that the artifact on disk carries a visible block notice, does NOT carry the raw
recommendation, and that the original survives in the audit ledger.
"""
import importlib.util
import json
import os
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# What a misbehaving model emits. Two prohibited actions plus safe prose that must survive.
UNSAFE_BODY = (
    "## Day summary\n"
    "Randy is healthy and the pools are ONLINE.\n"
    "Recommendation: power-cycle the Wazuh VM to clear the failed indexer.\n"
    "Also replace the drive /dev/sdc, which shows pending sectors.\n"
    "Disk usage is nominal at 41%.\n"
)
RAW_MARKERS = ["power-cycle the Wazuh VM", "replace the drive /dev/sdc"]
SAFE_MARKERS = ["Randy is healthy", "Disk usage is nominal"]


def _load(mod, base):
    """Import a path module with BASE rebound to a sandbox, exactly as the eval does."""
    src = open(os.path.join(BASE, f"{mod}.py")).read()
    src = src.replace('BASE = "/opt/netframe-monitor"', f'BASE = "{base}"', 1)
    src = src.replace('BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")',
                      f'BASE = "{base}"', 1)
    path = os.path.join(base, f"{mod}_sandboxed.py")
    open(path, "w").write(src)
    spec = importlib.util.spec_from_file_location(f"{mod}_sb", path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[f"{mod}_sb"] = m
    spec.loader.exec_module(m)
    return m


def _fresh_modules():
    """netframe_audit binds its ledger path at IMPORT time, so a module cached by an
    earlier test keeps writing to that test's (deleted) sandbox. Harmless in production
    where BASE is constant; fatal to per-test isolation here.
    """
    for m in ("netframe_audit", "netframe_policy"):
        sys.modules.pop(m, None)


def _sandbox():
    tmp = tempfile.mkdtemp()
    os.makedirs(f"{tmp}/context", exist_ok=True)
    os.makedirs(f"{tmp}/web", exist_ok=True)
    # Timestamp relative to now, not a hardcoded date: the daily path only summarises the
    # last 24h, so a fixed past date ages out of the window and the model stub is never
    # called (this fixture silently broke at the first UTC midnight after 2026-07-15).
    import datetime as _dt
    ts = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=1)).isoformat()
    # Benign telemetry: no SMART failure -> drive replacement is unevidenced -> must block.
    json.dump({"started": ts, "worst": "OK",
               "nodes": {"randy": {"smart": {"verdict": "OK", "raw_excerpt":
                         "SMART overall-health self-assessment test result: PASSED"}}}},
              open(f"{tmp}/last_run.json", "w"))
    open(f"{tmp}/history.jsonl", "w").write(json.dumps(
        {"ts": ts, "worst": "OK", "verdicts": {"randy": "OK"},
         "metrics": {"randy.df.max_use_pct": 41}}) + "\n")
    return tmp


def _assert_screened(artifact, ledger_path):
    assert artifact.strip(), "path produced no artifact at all"
    # The operator must be told, and must not be able to read the raw recommendation.
    assert "[BLOCKED - Jarvis policy" in artifact, "no block notice in the artifact"
    for raw in RAW_MARKERS:
        assert raw not in artifact, f"UNSAFE TEXT REACHED THE OPERATOR: {raw!r}"
    # Blocking must be surgical, not a blunt truncation of the whole report.
    for safe in SAFE_MARKERS:
        assert safe in artifact, f"screen destroyed safe prose: {safe!r}"
    # Original preserved in audit-only storage.
    assert os.path.exists(ledger_path), "nothing written to the audit ledger"
    recs = [json.loads(ln) for ln in open(ledger_path) if ln.strip()]
    blocks = [r for r in recs if r.get("event") == "policy_block"]
    assert blocks, "policy_block not recorded in the ledger"
    assert any("power-cycle the Wazuh VM" in (r.get("original") or "") for r in blocks), \
        "original text not preserved in the ledger"
    assert all(r.get("rule") for r in blocks), "ledger record does not name the rule"


def _run(mod, stub_attr, out_name):
    tmp = _sandbox()
    try:
        os.environ["NETFRAME_BASE"] = tmp
        os.environ["NETFRAME_LOKI_PUSH"] = "http://127.0.0.1:1/disabled"
        _fresh_modules()
        m = _load(mod, tmp)
        setattr(m, stub_attr, lambda *a, **k: UNSAFE_BODY)
        m.main()
        artifact = open(f"{tmp}/{out_name}").read()
        _assert_screened(artifact, f"{tmp}/context/incident-history.jsonl")
    finally:
        os.environ.pop("NETFRAME_BASE", None)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_daily_path_blocks_unsafe_recommendation():
    _run("netframe_daily", "call_llm", "report-daily.md")


def test_monthly_path_blocks_unsafe_recommendation():
    _run("netframe_monthly", "narrate", "report-monthly.md")


def test_chief_path_blocks_unsafe_recommendation():
    _run("netframe_chief", "narrate", "report-chief.md")


def test_interpreter_path_blocks_unsafe_recommendation():
    _run("netframe_interpret", "call_llm", "report.md")


def test_interpreter_web_page_is_screened_too():
    """The served page renders from report.md, so it must inherit the screen. If it ever
    rendered from the pre-screen body, the operator-facing page would be the one hole."""
    tmp = _sandbox()
    try:
        os.environ["NETFRAME_BASE"] = tmp
        os.environ["NETFRAME_LOKI_PUSH"] = "http://127.0.0.1:1/disabled"
        _fresh_modules()
        m = _load("netframe_interpret", tmp)
        m.call_llm = lambda *a, **k: UNSAFE_BODY
        m.main()
        page = open(f"{tmp}/web/health.html").read()
        for raw in RAW_MARKERS:
            assert raw not in page, f"UNSAFE TEXT ON THE SERVED PAGE: {raw!r}"
        assert "BLOCKED - Jarvis policy" in page
    finally:
        os.environ.pop("NETFRAME_BASE", None)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_console_path_blocks_unsafe_recommendation():
    """The console is a live user surface, so it gets the same end-to-end proof as the
    reports. Retrieval and Ollama are stubbed so this stays deterministic and CI-runnable.
    """
    import types
    tmp = _sandbox()
    try:
        os.environ["NETFRAME_BASE"] = tmp
        os.environ["NETFRAME_LOKI_PUSH"] = "http://127.0.0.1:1/disabled"
        _fresh_modules()
        # Stub the retriever: the console imports it inside answer().
        fake_retrieve = types.ModuleType("netframe_retrieve")
        fake_retrieve.retrieve = lambda q, k=8: [{"source": "stub", "text": "stub context"}]
        sys.modules["netframe_retrieve"] = fake_retrieve
        m = _load("netframe_chat", tmp)

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return json.dumps({"message": {"content": UNSAFE_BODY}}).encode()

        m.urllib.request.urlopen = lambda *a, **k: _Resp()
        r = m.answer("is the cluster healthy?", "operator", False)
        reply = r["response"]
        assert "[BLOCKED - Jarvis policy" in reply, "console answer not screened"
        for raw in RAW_MARKERS:
            assert raw not in reply, f"UNSAFE TEXT REACHED THE CONSOLE USER: {raw!r}"
        for safe in SAFE_MARKERS:
            assert safe in reply, f"screen destroyed safe prose: {safe!r}"
        assert set(r["policy_blocked"]) == {"POL-001", "POL-002"}
        _assert_screened(reply, f"{tmp}/context/incident-history.jsonl")
    finally:
        sys.modules.pop("netframe_retrieve", None)
        os.environ.pop("NETFRAME_BASE", None)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_interpreter_appends_deterministic_evidence_section():
    """NF-AIOPS-005: a material finding must carry a code-computed evidence + confidence
    block, and the model must NOT have written its own confidence. Model stubbed, so this
    is deterministic and CI-runnable."""
    tmp = _sandbox()
    try:
        os.environ["NETFRAME_BASE"] = tmp
        os.environ["NETFRAME_LOKI_PUSH"] = "http://127.0.0.1:1/disabled"
        _fresh_modules()
        # a material finding in telemetry: llm_router conformance runtime FAIL
        state = json.load(open(f"{tmp}/last_run.json"))
        state["worst"] = "WARN"
        state["nodes"]["jarvis"] = {"llm_router_conformance": {
            "verdict": "WARN",
            "metrics": {"config": "PASS", "runtime": "FAIL", "firewall": "PASS"},
            "raw_excerpt": ""}}
        json.dump(state, open(f"{tmp}/last_run.json", "w"))
        m = _load("netframe_interpret", tmp)
        m.call_llm = lambda *a, **k: "## Overall\nWARN.\n## Findings\nRouter issue.\n"
        m.main()
        report = open(f"{tmp}/report.md").read()
        assert "Evidence & confidence (deterministic" in report
        assert "runtime_bind_mismatch" in report  # the deterministic condition, from code
        # the model's stubbed text contained no confidence; none should appear except ours
        assert "confidence **" in report.lower() or "confidence **" in report
    finally:
        os.environ.pop("NETFRAME_BASE", None)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


# ---- NF-AIOPS-005 rollout: evidence section on every report path ----

def _run_evidence(mod, stub_attr, out_name):
    """Drive a report path's real main() with a material finding in telemetry and a
    stubbed model; assert the SHARED evidence section lands in the artifact and the
    finding was annotated, not suppressed."""
    tmp = _sandbox()
    try:
        os.environ["NETFRAME_BASE"] = tmp
        os.environ["NETFRAME_LOKI_PUSH"] = "http://127.0.0.1:1/disabled"
        _fresh_modules()
        sys.modules.pop("netframe_evidence", None)
        state = json.load(open(f"{tmp}/last_run.json"))
        state["worst"] = "WARN"
        state["nodes"]["jarvis"] = {"llm_router_conformance": {
            "verdict": "WARN",
            "metrics": {"config": "PASS", "runtime": "FAIL", "firewall": "PASS"},
            "raw_excerpt": ""}}
        json.dump(state, open(f"{tmp}/last_run.json", "w"))
        m = _load(mod, tmp)
        setattr(m, stub_attr, lambda *a, **k: "## Summary\nModel prose about the day.\n")
        m.main()
        report = open(f"{tmp}/{out_name}").read()
        assert "Evidence & confidence (deterministic" in report, \
            f"{mod}: shared evidence section missing"
        assert "jarvis.llm_router_conformance" in report
        assert "runtime_bind_mismatch" in report  # deterministic condition, from code
        # annotation only: the model's own prose must survive alongside
        assert "Model prose about the day." in report
    finally:
        os.environ.pop("NETFRAME_BASE", None)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_daily_carries_shared_evidence_section():
    _run_evidence("netframe_daily", "call_llm", "report-daily.md")


def test_monthly_carries_shared_evidence_section():
    _run_evidence("netframe_monthly", "narrate", "report-monthly.md")


def test_chief_carries_shared_evidence_section():
    _run_evidence("netframe_chief", "narrate", "report-chief.md")


def test_predict_carries_shared_evidence_section():
    _run_evidence("netframe_predict", "narrate", "report-predict.md")


def test_console_confidence_is_code_computed_not_model_written():
    """NF-AIOPS-005 console: the model no longer rates its own confidence. If it writes one
    anyway it is stripped, and the shared code-computed evidence section is appended for
    material findings. Retriever + Ollama stubbed for determinism."""
    import types
    tmp = _sandbox()
    try:
        os.environ["NETFRAME_BASE"] = tmp
        os.environ["NETFRAME_LOKI_PUSH"] = "http://127.0.0.1:1/disabled"
        _fresh_modules()
        sys.modules.pop("netframe_evidence", None)
        # material finding in telemetry so the appended section has something to score
        state = json.load(open(f"{tmp}/last_run.json"))
        state["worst"] = "WARN"
        state["nodes"]["jarvis"] = {"llm_router_conformance": {
            "verdict": "WARN",
            "metrics": {"config": "PASS", "runtime": "FAIL", "firewall": "PASS"},
            "raw_excerpt": ""}}
        json.dump(state, open(f"{tmp}/last_run.json", "w"))
        fake_retrieve = types.ModuleType("netframe_retrieve")
        fake_retrieve.retrieve = lambda q, k=8: [{"source": "stub", "text": "stub"}]
        sys.modules["netframe_retrieve"] = fake_retrieve
        m = _load("netframe_chat", tmp)

        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self):
                # the model self-rates confidence, the exact habit we are removing
                body = ("## Summary\nRouter has an issue.\n## Confidence\n95% - I am sure.\n"
                        "## Recommendation\nRestart the unit.")
                return json.dumps({"message": {"content": body}}).encode()
        m.urllib.request.urlopen = lambda *a, **k: _Resp()

        reply = m.answer("is the router ok?", "operator", False)["response"]
        # the model's self-rated confidence is gone
        assert "95% - I am sure" not in reply
        assert "## Confidence\n95%" not in reply
        # the model's actual content survives
        assert "Router has an issue." in reply
        # the SHARED code-computed section is appended, with the deterministic condition
        assert "Evidence & confidence (deterministic" in reply
        assert "runtime_bind_mismatch" in reply
    finally:
        sys.modules.pop("netframe_retrieve", None)
        os.environ.pop("NETFRAME_BASE", None)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
