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
| **VLAN 30 trunk -> pve4 + pve5 ports** | `OPEN` (30-min window) | Un-pins NPM/Vaultwarden/OpenWebUI from pve3 so today's 13h vault-outage class becomes a 15-min PBS restore to any node (AAR follow-on). RISK: live EX3400 change on ports carrying corosync - use `commit confirmed 5`, additive tag only (no new cables = no loop paths), cluster survives both ports dropping (5/7 quorate). Needs EX3400 creds via break-glass. Widens VLAN30 L2 domain to two more (already-trusted) node ports. |

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
| **Quarterly failure drill ("game day")** | `OPEN` (schedule) | ~1h, announced window, quarterly: deliberately fail one node's link (switch-side or cable), verify the node-down DM lands <15 min, triage runbook reaches the right diagnosis (link-state check), break-glass opens, recovery steps work. Drill #1 = the RKE2 failover test below. RISK: bounded (registry/Kuma only exposure; proven recovery in hand); never run casually/unannounced. |
| **RKE2: root-cause the failover failure + deliberate failover test** | `OPEN` | 2026-07-16: losing cp1 crash-looped rke2-server on BOTH survivors (~2000x/12h, startup fatal instead of waiting for etcd quorum; zombie shims) - the HA CP was not HA in practice. Recovery = stop + rke2-killall.sh + simultaneous restart (works, in the pve3 runbook addendum). ROOT CAUSE CONFIRMED same evening (journals): the 12:48-12:52 UTC PBS restores onto pve4 IO-starved rke2-cp2's disk (same thin pool) -> 2-member etcd leaderless -> both survivors fatal-exited on lost leases at 12:56:00 -> containerd-zombie restart deadlock. cp1 is BACK (rejoined same evening) - the test can run in any announced window; make it Game Day #1 (below). Repro = IO-stall a CP disk with one member down. --bwlimit policy adopted in runbooks. |

## Security

| Item | Status | Notes |
|---|---|---|
| **Break-glass credential file: populate (owner)** | `OPEN` (5 min) | Mechanism built+verified 2026-07-16 (Home-Lab `scripts/break-glass/`, AAR rec 11). Owner runs once on Ares: `export BW_SESSION="$(bw unlock --raw)" && ~/Home-Lab/scripts/break-glass/breakglass-refresh.sh` (first run writes the item list; review names vs Vaultwarden, re-run). Re-run after any rotation. Until populated, the circular dependency (switch/firewall creds only in Vaultwarden) remains. |
| **Ares full-disk encryption (decision)** | `OPEN` (decision) | Found 2026-07-16: Ares has NO LUKS. It holds root SSH keys to the whole cluster, the DR age key, and (once populated) the break-glass credential file - physical theft of the disk = the estate. Options: reinstall with LUKS (a day, the clean fix) vs encrypted home/keys-only vs accept (it's a desktop at home). Owner call; filed from the AAR risk discussion. |
| **VLAN 20 (BMC) egress block** | `OPEN` (GUI, ~15 min) | Found 2026-07-17 while assessing Supermicro CVE-2026-3821 (config-backup verified): VLAN 20 inbound is clamped (LAN/Servers blocked 2026-07-03) but its interface still carries legacy "trusted" pass rules -> **management AND internet**. A compromised BMC can phone home and reach VLAN 1. Fix in GUI (API keys are read-only): on the VLAN 20 interface, allow only established/related + (if BMCs need NTP/DNS) pinned services, then block all else incl. internet; keep Ares' L2 path (untouched by L3 rules). The un-done half of segmentation Phase 1.5. |
| **Supermicro CVE-2026-3821: check X10 exposure (owner)** | `OPEN` (5 min) | CVE still RESERVED publicly (2026-07-17); details only on the Supermicro Security Center (browser). Owner: open the advisory from the email, check if X10 boards are affected + fixed firmware for X10. Randy = X10DRU-i+, BMC fw 3.94, VLAN 20 isolated. If a fixed X10 BMC firmware exists, flash is low-risk (no host reboot) - hand off to a session to stage. |
| **VLAN 1 egress lockdown - enforcing** | `OPEN` (deliberately deferred) | Phase 1 (infra-scoped, log-only observe) is deployed and healthy (catch-all 0 hits, verified 2026-07-15). NOT rushed to enforce - owner chose to wait 2026-07-14, and there are real prereqs. **Enforce-phase plan (GUI, since the egress API key is now read-only):** (1) DHCP-reserve Ares .199/.100 so the exemption can't drift; (2) add multicast/broadcast pass (224.0.0.0/4, 239.0.0.0/8, 255.255.255.255) or UniFi .2 discovery gets blocked/noisy; (3) decide whether to exclude network gear .2/.50/.176 (legit phone-home); (4) add CDN ranges for RKE2 image pulls + switch Mist; (5) consider IPv6 egress (v4-only so far); (6) then flip rule 940 `c7fed07f` action pass->block (keep log). Rollback: set 940 back to pass. See `project-security-vlan-segmentation` memory. |

## AI-Ops / monitoring

| Item | Status | Notes |
|---|---|---|
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
| **Home Assistant: future add-ons / IoT VLAN 40** | `PASSIVE` | Mosquitto/ESPHome/Zigbee2MQTT as hardware arrives (Zigbee stick -> USB passthrough on pve5); when first IoT devices land on VLAN 40, add OPNsense HA(.60)->VLAN40 rules + mDNS strategy. Details in the install runbook. |
| **VoIP** | `OPEN` | FreePBX + 5x Cisco CP-8841 phones (deferred, post core infra). |
| **Cyberpunk monitoring dashboard** | `OPEN` | Live API integration for the wall dashboard. |
| **CCNA study cadence** | `OPEN` | Personal/study item (owner). |

## Hardware follow-ups (minor, from runbooks)

| Item | Status | Notes |
|---|---|---|
| pve3: discrete Intel NIC (i210/i350, ~$25) | `OPEN` (order) | Sidesteps the onboard I219's e1000e hang class entirely (offloads-off mitigates, does not cure). Swap during the same visit as the BIOS flag below. |
| pve3: BIOS "power on after AC loss" + e1000e recurrence watch | `OPEN`/`PASSIVE` | BIOS flag needs a console visit (headless WoL only works after a clean shutdown, not a hang). e1000e: offloads now off; if hangs recur, InterruptThrottleRate or a discrete NIC. |
| Randy: mark the dead PCIe slot on the chassis | `OPEN` | So it is never reused (Randy-PCIe-Slot-Recovery runbook). |
| Randy: re-secure re-routed SAS cables + watch CMOS battery | `OPEN` | Same runbook. |

## Parked (deliberate defer)

| Item | Status | Notes |
|---|---|---|
| Offsite restic -> cloud backup | `PARKED` | B2 preferred (egress freedom); target pools empty, nothing at risk. B2 vs AWS evaluated 2026-07-15. |

---

## Recently closed (this session)

**OPNsense DR backup: endpoint staleness CONFIRMED and FIXED (2026-07-17).** The
`VERIFY` concern was REAL, not a misdiagnosis (an intermediate wrong call by this
session, corrected once the live config was read on the box). `/api/core/backup/download/this`
served config cached at revision 2026-07-13 while the LIVE `/conf/config.xml` was
2026-07-16 — so the DR backup silently dropped the HA static map and every other
change for 3 days. **Fix (repo commits fac9452 + c5e6afb):** `backup.sh` now reads
the live config directly via the OPNsense VM's qemu guest agent (Ares -> ssh pve2 ->
`qm guest exec 100` -> gzip/base64 `/conf/config.xml`) — cache-proof and authoritative,
with hard validation (XML header + `</opnsense>` close + size floor) so a partial read
never overwrites a good backup. First run captured the true 07-16 config; DR backup
now verified to contain the HA map. LESSON: verify a DR backup against the authoritative
source (the file on the box), not the same channel that produces it.

**Home Assistant OPNsense static reservation: DONE (verified 2026-07-17).** A prior
session DID complete it correctly on 07-16 (bc:24:11:27:b2:5c -> 192.168.10.60); the
stale backup endpoint had hidden it. Verified in the running dhcpd (`host s_lan_2`) AND
persistent config.xml AND now the DR backup. HA holds .60 as a real reservation, not a
droppable lease. The "in-pool GUI rejection" note was moot (.60 is out-of-pool).


**Home Assistant owner account CLAIMED (2026-07-17):** the unclaimed-instance
open door is closed. Owner `kyle` created via the onboarding API; user step
done=True, second owner-create now 403. **Credentials handed to owner to file in
Vaultwarden (Services folder) - NOT yet filed** (bw was locked). Core config
(location/units) + integrations left for the owner to finish interactively (personal prefs).


**AAR recommendations 11-14 (2026-07-16 evening):** break-glass credential
mechanism built+verified (populate = owner action above); Grafana->pve4 +
Headscale->pve5 de-concentration (VLAN30 pins NPM/Vaultwarden/OpenWebUI to
pve3); node-unreachable triage runbook with node->MAC map; UPS state in every
collector cycle via NUT from Jarvis (WARNs when UPS monitoring itself is lost).
netframe-monitor PR #64 + Home-Lab #28. Estate cycle after all changes: worst=OK.


**pve3 outage RESOLVED (2026-07-16 evening):** real root cause = e1000e NIC
Hardware Unit Hang at 06:55:04 (box never lost power; 22,605 kernel msgs, 12.5h
wedged - why WoL failed all day). Fix persisted (tso/gso off on nic0). All guests
autostarted, cp1 rejoined (RKE2 3/3), NPM+Grafana migrated back (--bwlimit),
orphan LVs cleaned, prometheus container manually restarted, every front + full
netframe cycle verified green, recovery DM delivered. Full record:
`Home-Lab/vault/Runbook/Pve3-Outage-Recovery-2026-07-16.md`. Remaining spin-offs:
RKE2 failover test (HA section), BIOS auto-power-on (below), e1000e recurrence watch (PASSIVE).


**UNREACHABLE verdict + Grafana-independent node-down DM (PR #63, 2026-07-16):**
`classify()` now yields UNREACHABLE on ssh transport failure (line-start-keyed on
ssh's own error, spoof-proof vs journal text) instead of a dead node reading
`journal_errors=OK`/`smart=OK`; ranked with TIMEOUT/AUTH-FAIL. New `netframe_alert.py`
in every 15-min cycle DMs the operator via the on-call bot token on down/recovery
transitions (deterministic templates, no LLM, out-of-boundary by construction;
state advances only on successful send). Live-fire validated against the real pve3
outage: all 6 pve3 checks UNREACHABLE, DM delivered, repeat runs silent. Config
`/etc/netframe-alert.env` via service EnvironmentFile - which the new confdrift env
category flagged as drift on deploy (first real catch), then re-blessed.

**Config-drift env-file coverage (PR #62, 2026-07-16):** new `env` fingerprint category
on all nodes - every `EnvironmentFile=` referenced from `/etc/systemd/system/*.service`
plus `/etc/*.env`, hashed as name:content-hash lines (a root-only file appearing on a
remote node still drifts by name; Jarvis, which holds the custom service env files,
runs the check as root so content coverage is full there). Deployed, baseline
re-blessed, canary live-fire verified (new `/etc/*.env` -> DRIFTED -> clean). Also
hardened baselines against outages: `set-baseline` now merges over the previous
baseline (a bless while a node is down no longer wipes it or crashes the next check).

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
