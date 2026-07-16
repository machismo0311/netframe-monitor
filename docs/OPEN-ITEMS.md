# NetFRAME Open Items / Roadmap

**Purpose:** single source of truth for outstanding work, replacing scattered notes that
went stale. Each item carries a **verified status** as of the date shown, so this list can
be trusted rather than second-guessed. Private repo by design: several items name current
security gaps.

**Status legend:** `OPEN` (verified still open) · `VERIFY` (probably done, confirm before
acting) · `PARKED` (deliberate defer, nothing at risk) · `PASSIVE` (act only if
circumstances change).

_Last verified: 2026-07-15._

---

## Genuinely open (actionable)

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | **VLAN 1 egress lockdown - enforcing phase** | `OPEN` | Phase 1 (log-only observe) deployed 2026-07-11 via the rw API; the enforcing rules are NOT yet applied. Verified 2026-07-15. See `project-security-vlan-segmentation` memory. |
| 2 | **pve1 (Mac Mini) hardening** | `OPEN` | No `10-hardening.conf` drop-in present (verified 2026-07-15). pve1 is the standalone Pi-hole/Homepage host; it was outside the Ansible hardening fleet. |
| 3 | **Config-drift: cover service env files** | `OPEN` | `netframe_confdrift` fingerprints interfaces/sshd/sysctl but NOT env files like `/etc/llm_router.env`. The 2026-07-14 llm_router outage was env drift it would not have caught. Closing this prevents a recurrence at the source. |
| 4 | **QuarkyLab student-env Phase 03 packages** | `OPEN` | Add Fernanda's specific physics packages to the container definition (needs owner input on which). |

## Verify before acting (likely already done - stale notes)

| # | Item | Status | Notes |
|---|---|---|---|
| 5 | **Headscale Phase 2 (QuarkyLab migration)** | `VERIFY` | Memory says "still on commercial Tailscale," but QuarkyLab shows a Headscale-range IP `100.64.0.7` (2026-07-15) - looks migrated. Confirm the control plane, then close. Note: migration was meant to move with Fernanda's Mac in lockstep. |
| 6 | **pve5 corosync / resolv.conf permanent fix** | `VERIFY` | An old unchecked task ("fix corosync SSH to MagicDNS via interfaces"). Current state is healthy: resolv.conf uses Pi-hole `.177`/`.1`, corosync up on knet (node id 2), cluster quorate 7/7. Likely resolved; confirm and close. |

## Passive (act only if circumstances change)

| # | Item | Status | Notes |
|---|---|---|---|
| 7 | **Evidence-scoring weight recalibration** | `PASSIVE` | Calibrated to 7 frozen fixtures. Revisit only if a real incident shows the numbers are off (each score ships its factor breakdown, so a wrong number is legible). |
| 8 | **llm_router / Open WebUI policy boundary** | `PASSIVE` | Deliberately outside the policy boundary (general-purpose chat, no telemetry authority, no execution). Revisit ONLY if they gain tool-calling into the estate. |
| 9 | **Descoped conformance targets (NF-AIOPS-004)** | `PASSIVE` | Proxmox config assertions, NPM config-to-Git export - each needs a source-of-truth decision first. |
| 10 | **monitoring-stack repo reconcile** | `PASSIVE` | NF-AIOPS-002 noted live Grafana has more alert rules than the config-as-code repo. A known live/repo divergence to reconcile. |

## Parked (deliberate defer)

| # | Item | Status | Notes |
|---|---|---|---|
| 11 | **Offsite backup restic -> cloud** | `PARKED` | B2 vs AWS evaluated 2026-07-15; B2 is the better default (egress freedom for DR restores). Target pools currently empty, so cost ~$0 and nothing at risk. Revisit when there's offsite-worthy data. |

---

## Recently closed (this session, for context)

Console evidence integration + auto-restart hook; NPM/Pi-hole DNS-record audit check;
hardening drift detection; NPM admin password rotation; OPNsense egress-observe key
rotation+scoping. Plus corrections of several stale "open" notes now confirmed done:
Ansible hardening rollout, pve5 bogus gateway, OPNsense backup key scoping, Pi-hole
password (unified + vaulted). The full AI-Ops trustworthiness program is documented in
`docs/SESSION-BUILD-REPORT-2026-07-15.md` (public sanitized edition in the Home-Lab repo).

> **Maintenance rule:** when an item is finished, update BOTH this file and the relevant
> per-topic memory, and re-verify against live state rather than trusting the note - today
> surfaced four stale "open" items that were actually done.
