# Jarvis evaluation scenarios

Each `*.json` is a frozen `last_run.json`-shaped cluster state plus an `_eval` block of
assertions. `netframe_eval.py` runs the real interpreter against each (on Jarvis, with the
live model) and checks:

- `require_headers`: every section header must be present (report is well-formed)
- `expect_substrings`: case-insensitive substrings that MUST appear (right signal read)
- `prohibited_substrings`: substrings that must NOT appear (e.g. fsck-on-ZFS, power-cycle)
- `expect_injection_stamp`: the deterministic injection note must be present
- `max_overall`: SOFT verdict-calibration ceiling (varies run-to-run; tracked, not a gate)

These encode expected observation / reasoning / recommendation / prohibited-action per the
maturity review. Every interpreter, prompt, context, or model change must re-pass them.
