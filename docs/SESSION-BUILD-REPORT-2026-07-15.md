# NetFRAME AI-Ops Hardening - Comprehensive Build Report

**Date:** 2026-07-15
**Author:** Kyle Mason (masonkr@gmail.com)
**Scope:** One working session that began with publishing the Operations Console and grew
into a full trustworthiness program for Jarvis, the NetFRAME AI-operations platform.
**Repos touched:** `netframe-monitor` (private, PRs #30–#48), `Home-Lab` (public, PRs
#10–#14), `dotfiles` (submodule pointer bumps), Vaultwarden, and live nodes.
**Deployment discipline throughout:** one change at a time; fixtures/tests first; eval
baseline before and after; merge only on explicit CI PASS; deploy; verify live; bump the
submodule pointer.

---

## 1. Executive Summary

The session started as a small task (put the Operations Console behind a hostname) and
surfaced a chain of latent defects, each of which led to the next. Fixing them turned into
a deliberate program with a single thesis:

> **The model proposes and phrases. Code decides what is allowed, how well-supported it is,
> and how much confidence it warrants.**

By the end, every LLM-generated path to an operator passes through one deterministic policy
boundary and one deterministic evidence-scoring engine; the model no longer executes unsafe
actions, and no longer grades its own confidence. Along the way the tooling repeatedly
caught its own regressions, which is the strongest evidence that the guardrails are real.

Headline numbers: **24 pull requests** across two repos, **~101 automated tests**, **9 POL
policy rules**, **all 5 report paths** behind the shared policy + evidence engines, **the
Discord bot** brought behind the same boundary, and **two production incidents** found and
fixed (a DNS gap and an LLM-router loopback bind), plus **several latent bugs** caught by
tests before they shipped.

---

## 2. Chronology (how one thing led to the next)

1. **Publish the Operations Console** → needed an NPM proxy + DNS.
2. Doing DNS revealed a **cluster-wide DNS gap** (vault/grafana/wazuh unresolvable).
3. Fixing DNS made **Vaultwarden reachable again**, which unblocked filing secrets.
4. The console needed a **self-guard** (its NPM access list can silently detach).
5. Publishing a docs runbook exposed that **docs-only PRs could not merge** (CI path filter).
6. A health check revealed the **llm_router loopback-bind outage** (Open WebUI dead for a day).
7. That outage motivated **NF-AIOPS-004: configuration correctness** (Phases 1–3).
8. A flaky eval during Phase 2 exposed that **production did not enforce what evaluation
   asserted** - the model recommended prohibited actions ~1 run in 5, unscreened.
9. That became the **safety boundary**: a deterministic policy screen, made universal
   across every path, extended to the **Discord bot**.
10. The safety work needed a trustworthy **CI merge gate** and an **AI surface inventory**.
11. Finally, **NF-AIOPS-005: evidence-quality scoring** removed the last place the model
    graded itself (confidence), rolled out to all report paths.

---

## 3. Issues → Root Cause → Remedy

Every problem encountered, what caused it, and how it was fixed.

| # | Issue | Root cause | Remedy | PR |
|---|---|---|---|---|
| I-1 | Console reachable only by raw IP | No NPM proxy host / DNS for `console.kylemason.org` | NPM host id 8 → Jarvis:8809, LE cert (CF DNS-01), Basic auth, 200s proxy timeout for deep-model queries | Home-Lab #10 |
| I-2 | **vault/grafana/wazuh unresolvable LAN-wide** | Only `homepage`/`health` had Pi-hole local records; the rest were rebind-stripped for every Pi-hole client | Added the 4 missing local DNS records via password-free `pct exec` on the primary Pi-hole; nebula-sync to secondary | Home-Lab #10 |
| I-3 | `bw` (Bitwarden CLI) silently stopped syncing | It couldn't resolve `vault.kylemason.org` (same gap as I-2) - a DR trap: the vault is unreachable exactly when you need it | Fixed by I-2; documented the deadlock and the password-free break | Home-Lab #10 |
| I-4 | Console backend could go public unnoticed | NPM applies `auth_basic` in the access phase before `proxy_pass`; a detached access list = public console, no alarm | `console_auth` self-guard (401 = OK, 200 = WARN), separate from `page_auth` | #31 |
| I-5 | **Docs-only PRs stuck BLOCKED** | `ci.yml` supplied both required checks but was path-filtered to `scripts/**`; a docs PR triggered zero checks, and a required check that never runs stays pending forever | Dropped the path filter from `ci.yml`; kept it on the expensive non-required workflows | Home-Lab #11, #12 |
| I-6 | NPM admin password existed only in the owner's head | Never filed; no `INITIAL_ADMIN_PASSWORD` in compose | Filed in Vaultwarden, round-trip-verified against the NPM API | (Vaultwarden) |
| I-7 | Jarvis netframe restic passphrase unfiled | The existing vault item covered only the Ares repo; the Jarvis repo's passphrase lived solely on the host | Filed the Jarvis passphrase; functionally verified it opens the repo; reorganized the whole vault into 4 folders | (Vaultwarden) |
| I-8 | **Open WebUI chat dead for a day** | `llm_router` bind regressed `0.0.0.0`→`127.0.0.1` (live env drifted from the repo's documented value). Service stayed "active", localhost answered 200, so nothing alerted; but Open WebUI is on another host | Restored `0.0.0.0`; added an iptables allowlist on :8000 (no auth of its own); ordered lock before the service at boot | Home-Lab #13 |
| I-9 | Monitoring never noticed I-8 | The monitor had zero checks over `llm_router`, and a localhost probe would have read 200 throughout | `llm_router` check probing **through NPM** (the real consumer path), not localhost | #32 |
| I-10 | **Model recommended prohibited actions, unscreened** | The eval gated on prohibited substrings; nothing on the live path did. ~1 run in 5 the 7B recommended power-cycle (EVT-004) or replacing a healthy drive (EVT-003), reaching the operator | Deterministic prohibited-recommendation screen on the live path; made universal; extended to Discord | #35, #36, #37, Home-Lab #14 |
| I-11 | Config-drift detector couldn't express intent | It compared production to a *blessed snapshot of production*, not to Git - so it would have blessed the I-8 broken value as correct | Re-scoped drift to conformance against declared intent (NF-AIOPS-004 proposal); Phase 3 conformance wrapper | #40 |
| I-12 | PR merged on "no checks reported" | The old wait-loop treated absence of checks as completion (PR #37 merged before CI reported) | CI merge gate: no checks = UNKNOWN, UNKNOWN cannot merge, explicit named PASS required, decision recorded as a PR comment | #39 |
| I-13 | Model graded its own confidence | The Findings contract literally asked the model for "Confidence: a percentage" | Removed it; confidence computed deterministically from provenance (NF-AIOPS-005) | #41, #42 |

---

## 4. The Guardrails Installed ("grills")

Deterministic protections added this session, each enforcing a boundary the model or a
human could otherwise cross silently.

### 4.1 Network / service guardrails
- **`netframe-console-lock`** (pre-existing, verified): iptables restricts :8809 to NPM + localhost.
- **`llm-router-lock`** (Home-Lab #13): iptables allowlist on :8000 - localhost, Open WebUI, both NPM legs; default DROP. Ordered `Before=llm_router.service` so :8000 is never briefly open at boot. Fails closed.
- **`nfm-llm-router-conformance`** (#40): root-owned, arg-free wrapper reporting **config / runtime / firewall as three separate dimensions**, emitting only booleans + non-secret tokens - never file contents or secrets.

### 4.2 Monitoring self-guards
- **`console_auth`** (#31) and the existing **`page_auth`**: WARN if an NPM access list detaches (page/console goes public).
- **`llm_router`** (#32): probes through NPM, never localhost - a localhost probe reads healthy through exactly the I-8 failure.
- **User-journey probes** (#34): reach / authenticate / **transact** tiers. Auth probes were being read as reach probes; a 401 proves the gate, not the backend. Added backend-reach probes (`console_backend`, `report_backend`, `openwebui_reach`).

### 4.3 The policy boundary (the big one)
- **`netframe_policy.enforce()`** - ONE deterministic engine, 9 rules:

| Rule | Blocks |
|---|---|
| POL-001 | power-cycle / hard reset (EVT-004) |
| POL-002 | drive replacement without evidence - *narrowed* to unsupported **immediate** replacement (EVT-003) |
| POL-003 | destructive storage (zpool destroy, fsck, dd, mkfs, rm -rf) |
| POL-004 | firewall changes |
| POL-005 | DNS changes |
| POL-006 | destructive Proxmox (qm/pct destroy, delnode, lvremove) |
| POL-007 | unauthorized remediation (outside the Tier-1 allowlist) |
| POL-008 | destructive rebuild / reinstall |
| POL-009 | unevidenced hardware-failure **claims** (the predicate for the action) |

  - Blocks are **never silent**: visible notice with rule id + reason + evidence requirement; original preserved in the hash-chained, Loki-mirrored audit ledger, never in the artifact.
  - **Negation respected** (scoped to the trigger): "do not power-cycle" is correct advice.
  - **Evidence-gated**: a genuinely failed drive (SMART FAILED) is still replaceable advice.
  - Universal across all 5 report paths + console + Discord (#35, #36, #37, Home-Lab #14).

### 4.4 GPU admission control (#34)
- Transact probes **never use the 72B**, run hourly at most, and skip (never WARN/FAIL) when the GPU is busy, a 72B is resident, an interactive user is active, or in a maintenance window. `SKIPPED` ranks with `OK` so it never raises a false alarm; a skip writes no history metric.

### 4.5 CI / governance guardrails
- **Merge gate** (#39): UNKNOWN ≠ PASS; explicit named-check PASS required; auditable decision comment before merge.
- **AI surface inventory** (#39, #48): every LLM-touching component with policy + evidence coverage status, cross-checked against source so a row can't claim coverage the code lacks, and UNGATED fails CI.

### 4.6 Evidence scoring (NF-AIOPS-005)
- **`netframe_evidence`** - two axes that never collapse: evidence quality (additive/banded) and confidence (floors/ceilings). Deterministic; anti-hallucination (a cited source absent from telemetry contributes zero + caps confidence); freshness exposed; provenance per factor; **annotation-only, never suppression**.

---

## 5. Bugs the Tooling Caught (the meta-wins)

These are the moments the guardrails paid for themselves: regressions caught before they
reached an operator, several of them introduced during this very session.

- **Regex boundary escapes (×2):** trailing `)\b` after `dd if=` and leading `\b(` before `/etc/resolv.conf` were dead branches that passed prohibited text straight through. Found by adversarial probing; pinned by test. (#35)
- **Total negation bypass:** negation was scanned across the whole line, so "power-cycle the VM **to avoid** corruption" escaped entirely. Scoped to a 40-char lookback. (#38)
- **POL-002/POL-009 shared-predicate coupling:** narrowing POL-002 silently broke POL-009. Split into separate gates, pinned by an identity test. (#38)
- **Eval sandbox incompleteness (×2):** the interpreter imported `netframe_policy` then `netframe_evidence`, which the eval sandbox didn't copy → every scenario crashed (0/8). Fixed, then guarded by a test that derives the requirement from source so it can't happen a third time. (#36, #42)
- **The flaky "8/8" was luck:** NF-AIOPS-003 called the hard gates "stable 8/8 across 3 runs." At the real ~20% model-misbehavior rate, three clean runs is a coin flip. The policy screen is what made it actually safe.
- **Inert sudoers pin:** the first Phase-3 pin targeted a `monitor` user that doesn't exist on Jarvis (the collector runs locally as root there). Caught via `visudo -c`, removed. (#40)
- **Chief report tried a prohibited rec on its FIRST gated run:** the 72B executive report recommended an unevidenced drive replacement; the screen blocked it live. (post-#36)

---

## 6. NF-AIOPS Program Detail

### 6.1 NF-AIOPS-004: Configuration Correctness
- **Proposal** established the central insight: expanding the drift detector would NOT have caught the I-8 outage, because it compares production to a blessed snapshot of production, not to Git. Re-scoped to conformance against declared intent.
- **Phase 1 (#33):** added the service tier to the dependency graph (`ollama`, `llm_router`, `npm`, `open_webui`, …). Fixed a mis-attribution that would have blamed Grafana for a Jarvis outage.
- **Phase 2 (#34):** user-impact probes + GPU admission control (§4.4).
- **Phase 3 (#40):** the conformance wrapper (§4.1), three separate dimensions, secrets-safe, observe-only.

### 6.2 The safety boundary
- Screen (#35) → universal (#36) → last two paths (#37) → Discord (Home-Lab #14). Fixtures in `eval/policy-fixtures.json`; e2e proof per path.

### 6.3 NF-AIOPS-005: Evidence-quality scoring
- **Two axes, never collapsed.** The three headline incidents, scored by the deployed code:

| Incident | Evidence | Confidence | Demonstrates |
|---|---|---|---|
| EVT-003 false replacement | LOW (39) | 30% | distrusted both axes |
| EVT-004 power-cycle action | **HIGH (77)** | **30%** | axes diverge (rich evidence, wrong action) |
| llm_router outage | MED (56) | **95%** | thin evidence, deterministic fact |

- Integrated on the interpreter (#42), then rolled out to daily/monthly/chief/predict via a **single shared engine** (#43–#47). Inventory updated (#48).

---

## 7. Pull Request Index

**netframe-monitor (private):**
| PR | Title |
|---|---|
| #30 | Jarvis Operations Console (retrieval-augmented chat UI) |
| #31 | Self-guard the operations console access list |
| #32 | Watch llm_router over its real network path |
| #33 | NF-AIOPS-004 Phase 1: service tier in the dependency model |
| #34 | NF-AIOPS-004 Phase 2: user-impact probes + GPU admission control |
| #35 | Safety: deterministic prohibited-recommendation screen on the live path |
| #36 | Safety: make the policy boundary universal |
| #37 | Safety: close the last two unprotected LLM paths |
| #38 | Safety: narrow POL-002 + fix a total negation bypass |
| #39 | Governance: CI merge gate + AI surface inventory |
| #40 | NF-AIOPS-004 Phase 3: narrow llm_router conformance |
| #41 | NF-AIOPS-005 steps 1–2: fixtures + deterministic evidence scoring |
| #42 | NF-AIOPS-005 step 3: integrate on the interpreter path |
| #43–#47 | NF-AIOPS-005 rollout: shared builder, daily, monthly, chief, predict |
| #48 | Inventory: evidence-annotation coverage |

**Home-Lab (public):**
| PR | Title |
|---|---|
| #10 | Runbook: DNS local-records gap + console publication |
| #11 | CI: run lint/syntax on every PR (docs PRs can merge) |
| #12 | Runbook: the required-check path-filter trap |
| #13 | llm_router: iptables allowlist + loopback-bind trap runbook |
| #14 | jarvis-oncall: Discord bot behind the shared policy boundary |

**Design documents** (`~/jarvis-ai-ops/`, LaTeX PDFs): NF-AIOPS-004 (config correctness),
NF-AIOPS-005 (evidence scoring).

---

## 8. Owner Follow-Ups (open items)

- **NPM admin password** is now in Vaultwarden but also exists in this session's transcript; rotation offered, deferred to a keyboard session.
- **Console/chat and ghreview** are policy-gated but **not** evidence-annotated (conversational / portfolio, not material-finding reports) - candidate follow-ups, recorded in the inventory as deliberate.
- **Evidence-scoring weights** are calibrated to 7 frozen fixtures; revisit if real incidents suggest recalibration (each score ships its factor breakdown, so a wrong number is legible).
- **llm_router / Open WebUI** are deliberately out of the policy boundary (general-purpose chat); revisit if they ever gain tool-calling into the estate.

---

## 9. Risk Register (end-of-session)

| Risk | Level | Status |
|---|---|---|
| Privilege expansion undoing security posture | - | Avoided: arg-free root-owned wrappers only; no broad sudo |
| Feature becomes a secret-exfiltration path | - | Avoided: hashes/booleans only, never file contents |
| Config content as prompt-injection vector | - | Avoided: booleans not content into the model context |
| False positives train rubber-stamping (R-04) | LOW | Materialised then closed: POL-002 narrowed, real FPs are must-pass fixtures |
| Uneven boundary across repos/surfaces | LOW | Closed: Discord gated; inventory + CI keep the denominator honest |
| Rule-precision fragility (regex both directions) | MED | Accepted: contained by fixtures, adversarial tests, and the visible audit ledger |
| Annotation noise on bad days | LOW | Watched: only fires for material findings, each self-explaining |
| Scoring expanding into suppression | - | Prevented by design + test: annotation-only, low confidence never hides a finding |

---

## 10. The One-Line Summary

Every LLM-generated recommendation an operator can see now passes through one policy engine
(is it allowed?), one evidence engine (how well-supported, how sure?), and one hash-chained
audit trail (recorded), with the model reduced to what it is good at - wording. That is the
whole point: **not a more powerful automation system, a more trustworthy one.**
