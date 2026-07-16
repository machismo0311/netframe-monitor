# NetFRAME Open Items / Roadmap

**This is the single source of truth for outstanding work.** When "what's next?" is asked,
it references this file. New todo items get committed here. It consolidates what used to be
scattered across: memory notes, the Home-Lab README "Planned" list, the Obsidian
`00 - Homelab MOC.md` roadmap, individual runbook checklists, and the assessment docs.

Each item has a **verified status** as of the date shown, so the list can be trusted.
Private repo by design: some items name current security gaps.

**Status:** `OPEN` (verified open) · `IN-PROGRESS` (started, steps remain) · `VERIFY`
(probably done, confirm first) · `PARKED` (deliberate defer) · `PASSIVE` (act only if
things change).

_Last full reconcile: 2026-07-15._

---

## Network & connectivity

| Item | Status | Notes |
|---|---|---|
| **WAN failover - FirstNet 5G (MR7400)** | `IN-PROGRESS` | Multi-step implementation checklist in `Home-Lab/vault/Runbook/WAN-Failover-FirstNet-MR7400-Plan-2026-07-12.md` (remove legacy .1.1 VIP, cable MR7400 to nic2, pve2 vmbr2, OPNsense WAN2 failover group, test, WAN2-down Grafana alert). The #1 SPOF (single WAN) reducer. |
| **OPNsense CARP HA pair** | `OPEN` | Removes the top-ranked SPOF (OPNsense = 1 VM on pve2). Part of the HA roadmap. |
| **DAC 10G uplink -> fiber** | `OPEN` | `xe-0/2/3 -> UniFi SFP2`: replace the DAC with fiber optics. |

## Headscale / STUDENT REMOTE ACCESS

> **CORRECTION 2026-07-15 (retracts the earlier "KEY FINDING"):** the student access
> model was ALREADY DECIDED AND BUILT 2026-07-06 - **Cloudflare Tunnel**, not Headscale.
> `cloudflared` on QuarkyLab (active+enabled, tunnel `quarkylab`) publishes SSH at
> `quarkylab.kylemason.org`; students/researchers install cloudflared locally and SSH
> with a per-account key (`add-cluster-key.sh studentNN`). Headscale is deliberately
> **internal admin mesh only** - exposing it off-LAN was explicitly vetoed in
> `Home-Lab/vault/Runbook/QuarkyLab-Cloudflare-Access.md`; user docs:
> `QuarkyLab-Researcher-Access.md` + `QuarkyLab-Student-Quickstart.md` + `QuarkyLab-Account-Onboarding.md`.
> **Re-verified end-to-end 2026-07-15** (SSH through the tunnel from Ares succeeded).
> The earlier finding ("no student access path exists, decision needed") was wrong - it
> missed these runbooks. Remaining real gaps are below.

| Item | Status | Notes |
|---|---|---|
| **Cloudflare Access layer (email gate)** | `OPEN` | Tunnel endpoint is currently gated by SSH keys ONLY. Access (Zero-Trust free tier, 50 users, email OTP) is designed in the runbook but needs the manual Zero-Trust signup (team name + payment method on file). Adds a second independent gate before port 22. |
| **Onboard first actual students** | `OPEN` | Path is ready: collect pubkey -> `add-cluster-key.sh studentNN` -> send them `QuarkyLab-Researcher-Access.md` steps (user `studentNN`). 0 student keys loaded so far. Blocked only on Kyle having students to onboard. |
| **Ansible student on/off-boarding playbook** | `OPEN` (blocked on roster) | **Full build plan: [`STUDENT-ONBOARDING-PLAN.md`](STUDENT-ONBOARDING-PLAN.md)** (4 phases, 20 checkboxes). Kyle's spec 2026-07-15: students get the PDF -> return info -> master roster; playbook reads roster and builds everything (onboard) / revokes key + wipes account when they leave the class (offboard). Only Phase 0 (4 decisions, ~10 min) needs Kyle before the build; Phases 1-3 can be built+tested with fake entries pre-semester. When Kyle asks about "the onboarding process", THAT plan file is the answer. |
| **Phase 2: Ares MagicDNS fix** | `LOW-VALUE POLISH` | Admin convenience only (hostnames over tailnet on Kyle's own workstation); NOT on the student path. Deprioritise. |
| **Phase 3: device migration** | `VERIFY (mostly DONE)` | 2026-07-15 live check: 9 nodes on Headscale incl QuarkyLab (node 7) + Fernanda's machine (node 9, FUS22-009897, `fernanda` user). Only 2 users: kyle, fernanda. Kyle + Fernanda are migrated = Phase 3 effectively done for the researcher. Note Fernanda's node is offline since 2026-07-06 (expected off-LAN: Headscale control plane is LAN-only by design; she reaches QuarkyLab via the Cloudflare tunnel like everyone else remote). |
| **Phase 4: CT 105 -> VLAN 30** | `OPEN` | Move the Headscale container to VLAN 30, update login-server URLs. Internal-only change; not on the student path. |

## High Availability roadmap (big, references vault `High Availability MOC`)

| Item | Status | Notes |
|---|---|---|
| WAN failover | see Network above | |
| **Compute HA** | `OPEN` | `ha-manager` + Ceph or ZFS replication for VM/CT failover. |
| **Storage redundancy** | `OPEN` | Randy is a single storage node (SPOF #2). |
| **EX3400 switch Virtual Chassis** | `OPEN` | Switch-level redundancy. |

## Security

| Item | Status | Notes |
|---|---|---|
| **VLAN 1 egress lockdown - enforcing** | `OPEN` (deliberately deferred) | Phase 1 (infra-scoped, log-only observe) is deployed and healthy (catch-all 0 hits, verified 2026-07-15). NOT rushed to enforce - owner chose to wait 2026-07-14, and there are real prereqs. **Enforce-phase plan (GUI, since the egress API key is now read-only):** (1) DHCP-reserve Ares .199/.100 so the exemption can't drift; (2) add multicast/broadcast pass (224.0.0.0/4, 239.0.0.0/8, 255.255.255.255) or UniFi .2 discovery gets blocked/noisy; (3) decide whether to exclude network gear .2/.50/.176 (legit phone-home); (4) add CDN ranges for RKE2 image pulls + switch Mist; (5) consider IPv6 egress (v4-only so far); (6) then flip rule 940 `c7fed07f` action pass->block (keep log). Rollback: set 940 back to pass. See `project-security-vlan-segmentation` memory. |

## AI-Ops / monitoring

| Item | Status | Notes |
|---|---|---|
| **Config-drift: cover service env files** | `OPEN` | `netframe_confdrift` fingerprints interfaces/sshd/sysctl but NOT env files like `/etc/llm_router.env` - the 2026-07-14 outage was env drift it would not have caught. |
| **QuarkyLab student-env Phase 03 packages** | `OPEN` | Add the researcher's specific physics packages to the container def (needs owner input). |
| Evidence-scoring weight recalibration | `PASSIVE` | Revisit only if a real incident shows the numbers are off. |
| llm_router / Open WebUI policy boundary | `PASSIVE` | Deliberately out of the boundary; revisit only if they gain tool-calling. |
| Descoped conformance targets (Proxmox, NPM) | `PASSIVE` | Each needs a source-of-truth decision first. |
| monitoring-stack repo reconcile | `PASSIVE` | Live Grafana has more alert rules than the config-as-code repo (NF-AIOPS-002). |

## Jarvis LLM platform (enhancements / known limitations)

| Item | Status | Notes |
|---|---|---|
| **RAG auto-reindex** | `OPEN` | RAG index rebuild is manual; a nightly systemd timer would auto-refresh. |
| **TLS for `netframe.local` fronts** | `OPEN` | `llm`/`chat.netframe.local` are HTTP-only; step-ca could issue certs. |
| Streaming in `llm_router` | `PASSIVE` | Responses are non-streamed; nice-to-have. |
| Claude API fallback | `PASSIVE` | Deliberately disabled until `ANTHROPIC_API_KEY` is set (local-only by choice). |

## Other projects

| Item | Status | Notes |
|---|---|---|
| **Home Assistant: onboarding** | `OPEN` | HAOS 18.1 VM 110 on pve5 installed 2026-07-16 (http://homeassistant.netframe.local:8123, **192.168.10.60** static-mapped). First visit creates the OWNER account - do it soon (unclaimed instance) and file creds in Vaultwarden. Runbook: `Home-Lab/vault/Runbook/Home-Assistant-Install-2026-07-16.md`. |
| **OPNsense config-backup endpoint staleness** | `VERIFY` | 2026-07-16: `/api/core/backup/download/this` kept returning the 2026-07-13 revision even after a DHCP static-map change was saved, applied and demonstrably live (VM re-leased .60). The nightly `opnsense-config-backup` (Ares cron 03:17) uses this endpoint -> DR backups may silently miss recent changes. Check the next nightly backup contains staticmap `bc:24:11:27:b2:5c`; if absent, investigate (endpoint choice or caching) and fix backup.sh. |
| **Home Assistant: future add-ons / IoT VLAN 40** | `PASSIVE` | Mosquitto/ESPHome/Zigbee2MQTT as hardware arrives (Zigbee stick -> USB passthrough on pve5); when first IoT devices land on VLAN 40, add OPNsense HA(.60)->VLAN40 rules + mDNS strategy. Details in the install runbook. |
| **VoIP** | `OPEN` | FreePBX + 5x Cisco CP-8841 phones (deferred, post core infra). |
| **Cyberpunk monitoring dashboard** | `OPEN` | Live API integration for the wall dashboard. |
| **CCNA study cadence** | `OPEN` | Personal/study item (owner). |

## Hardware follow-ups (minor, from runbooks)

| Item | Status | Notes |
|---|---|---|
| Randy: mark the dead PCIe slot on the chassis | `OPEN` | So it is never reused (Randy-PCIe-Slot-Recovery runbook). |
| Randy: re-secure re-routed SAS cables + watch CMOS battery | `OPEN` | Same runbook. |

## Parked (deliberate defer)

| Item | Status | Notes |
|---|---|---|
| Offsite restic -> cloud backup | `PARKED` | B2 preferred (egress freedom); target pools empty, nothing at risk. B2 vs AWS evaluated 2026-07-15. |

---

## Recently closed (this session)

Student-onboarding doc drift fixed (Home-Lab #20): student-guide README rewritten off
the dead Headscale plan, quickstart (vault + mirror + /data/shared on-box) now routes
via the Cloudflare tunnel instead of the LAN IP, VS Code Remote-SSH warning added to
the student guide (sshd forwarding is off for students), both PDFs recompiled; guide
flow dry-run end-to-end (tunnel SSH -> sbatch job COMPLETED on the RTX 8000).
Console evidence integration + auto-restart hook; NPM/Pi-hole DNS-record audit check;
hardening drift detection; NPM admin password rotation; OPNsense egress-observe key
rotation+scoping; pve1 hardening (into the Ansible fleet + drift-check). Stale "open" notes confirmed DONE: Ansible hardening rollout, pve5 bogus
gateway, OPNsense backup key scoping, Pi-hole password (unified + vaulted). Full AI-Ops
program: `docs/SESSION-BUILD-REPORT-2026-07-15.md`.

> **Maintenance rules:**
> 1. New todo items are committed HERE. "What's next?" references this file.
> 2. When closing an item, update this file AND the relevant memory, and **re-verify
>    against live state** - this reconcile found multiple stale "open" notes that were done.
> 3. The public Home-Lab README "Planned" list and the vault MOC roadmap are the
>    coarser, public-facing views; THIS file is authoritative. Keep them from drifting.
