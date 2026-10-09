# Node-local artifacts

Files deployed to specific nodes outside `/opt/netframe-monitor/`, tracked here for
source-of-truth. Not copied by the top-level deploy block.

| File | Deploy to | Purpose |
|---|---|---|
| `<cluster-node>-nfm-prom-health` | **`<cluster-node>`**`:/usr/local/sbin/nfm-prom-health` (root:root 0755) | Fixed, argument-less wrapper that probes Prometheus `/-/healthy` on the observability core (the CT that evaluates the alert rules), with a session bound so the monitor's fan-out cannot exhaust ssh sessions. **This copy mirrors the canonical source in the program repository's P2 cut-over package** (`observability/implementation/deployment/p2-cutover/bin/nfm-prom-health`), which is what is installed; it is byte-identical to the deployed file (sha256 `2f3cba43...`, reconciled 2026-10-08). The earlier copy here still probed the retired Grafana-stack CT: the cut-over replaced the deployed wrapper but never updated this mirror. |
| `<cluster-node>-nfm-npm-dns-audit` | `<cluster-node>:/usr/local/sbin/nfm-npm-dns-audit` (root:root 0755) | Argument-free wrapper that enumerates NPM proxy-host `server_name`s (from the LXC-101 bind mount, no admin API/password) and resolves each against the primary Pi-hole (`.177`), emitting `name=OK\|MISSING` + a `total=/missing=` summary. Catches the 2026-07-15 failure class: a published NPM host with no Pi-hole local record (rebind-stripped, unresolvable LAN-wide). Feeds the `npm_dns` check on the <cluster-node> node. Sudoers pin (note the `""` = no args): `monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-npm-dns-audit ""`. Emits only hostnames + status, no secrets. |
| `jarvis-nfm-llm-router-conformance` | `jarvis:/usr/local/sbin/nfm-llm-router-conformance` (root:root 0755) | NF-AIOPS-004 Phase 3. Argument-free conformance wrapper for llm_router. Reports **config / runtime / firewall as three separate dimensions** (never one boolean), emitting only booleans + non-secret expected/actual tokens - never file contents, env values, or secrets. On Jarvis the collector runs locally **as root** (llm_router is Jarvis's own service), so it invokes the wrapper directly with **no sudoers pin**; the wrapper stays root-owned/arg-free/Git-tracked so extending it to a remote node drops straight into the standard `monitor` + `""`-no-args sudoers pattern. Observe-only: a drift becomes a screened recommendation through the existing gated path; it never edits config, restarts, or touches the firewall. |

## <opnsense-host>-nfm-wan-posture
Deployed to `<opnsense-host>:/usr/local/sbin/nfm-wan-posture` (root:root 0755).
Argument-free, root-owned wrapper that reports the estate's dual-WAN failover posture:
whether a standby path is **armed**, which **group** provides it, and which path pf is
**actually** routing through. Feeds the `wan_failover` check on that node. Sudoers pin
(note the `""` = no arguments permitted):

    monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-wan-posture ""

**Why it exists.** The wall display asserts, in green, that a primary-WAN failure is
survivable. Between 2026-08-15 and 2026-09-09 it asserted that for 25 days while the LTE
standby was dead, because the fact was absent and absence rendered as health. The two facts
that make the claim true live inside the firewall guest - the gateway groups and policy
rules in the live config, and the route-to actually programmed in pf - and the wall display
host holds no credential for either, by design. Deriving them here publishes them through
`last_run.json`, which that host already reads over its existing forced command, so the wall
gains the fact and gains no privilege.

**Armed is a conjunction, not a lookup.** A gateway group that exists but that no *enabled*
rule routes through is a dormant object, not failover. Both conditions are required.

**The live config file is the only authority.** The firewall's backup API served a stale
snapshot during the 2026-09 investigation, missing three rules, which produced two
consecutive wrong "failover is not armed" findings.

Emits only a bounded key=value vocabulary - never config text, a rule body, or a credential.
Read-only: it starts nothing, stops nothing and changes no configuration.

## <gpu-research-node>-nfm-wazuh-indexer-restart
Deployed to `<gpu-research-node>:/usr/local/sbin/nfm-wazuh-indexer-restart` (root:root 755).
The ONLY action the `monitor` user can take on the GPU research node beyond read-only checks:
the EVT-004 in-place wazuh-indexer restart inside VM 104 via the guest agent
(never a power-cycle). Sudoers pin (in `/etc/sudoers.d/monitor`, note the `""` =
no arguments permitted):

    monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-wazuh-indexer-restart ""

Invoked by `netframe_remediate.py` action `restart-wazuh-indexer` after explicit
human approval. Live-fire validated 2026-07-15 (indexer returned to active).

## <siem-vm>-nfm-wazuh-health
Deployed to `<siem-vm>:/usr/local/sbin/nfm-wazuh-health` (root:root 0755). **Not yet deployed.**
Argument-free, root-owned wrapper that reports the SIEM's health as seven measured inputs:
manager, indexer, dashboard, log shipper, agents, authentication-telemetry freshness and event
drops. Feeds the `wazuh` and `wazuh_coverage` checks. Sudoers pin, source in
`azuh-nfm-wazuh-health.sudoers` (note the `""` = no arguments permitted):

    monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-wazuh-health ""

**Why it exists.** The previous SIEM check read only the manager's daemon list. For eight days it
showed the SIEM green while the search backend was down, the dashboard returned 503, the log
shipper could not deliver, and most agents had silently stopped sending authentication telemetry.

**Freshness uses authentication successes only.** A journal reader can stall on the system journal
while still holding user journals, which keep feeding session and sudo alerts. Only an sshd
"Accepted" line (rule 5715), which comes through the system journal, proves the reader is alive.
On hosts the monitor visits, its own login is the canary.

**Cluster health** is read with the indexer's local admin client certificate, in place, for one
fixed GET whose response yields only the status word. A dedicated least-privilege credential is
a deployment decision.

Emits only a bounded key=value vocabulary and an `end=1` sentinel; any failure is a fixed token.
Read-only: it starts nothing, stops nothing and changes no configuration.

## nfm-smart (every node with a `smart` check)
Deployed to `<node>:/usr/local/sbin/nfm-smart` (root:root 0755), the same file on every node,
with an optional per-node policy at `/etc/netframe/nfm-smart.conf` (root:root 0644; tracked as
`<node>-nfm-smart.conf`). Sudoers pin, source in `nfm-smart.sudoers` (note the `""` = no
arguments permitted), replacing the bare `/usr/sbin/smartctl` grant in `/etc/sudoers.d/monitor`:

    monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-smart ""

**Why it exists.** The `smart` check looped over `lsblk` names and ran `smartctl -H -A /dev/sdX`
with no device type. Behind a MegaRAID controller that is the wrong path for some disks. On the GPU
research node the SATA drives failed SMART RETURN STATUS (DID_BAD_TARGET, about 1500 kernel errors
a day), smartctl fell back to "PASSED ... based on an Attribute check", and the check read OK. On
the storage host a RAID virtual drive with no SMART read "SMART Health Status: OK" while its two
member disks were never polled. The old grant also let the monitor user pass any smartctl argument.

**Target selection** comes from the controller topology, so each physical disk is polled once:
megaraid_sas channel >= 2 is a virtual drive (explicit, no smartctl call); channel 0/1 is a physical
disk on its plain path, or on `/dev/bus/H -d sat+megaraid,T` when the node policy says the plain
path is broken for SATA; a megaraid PD with no block device (RAID member, unconfigured disk) is
polled as `/dev/bus/H -d megaraid,N`; a USB disk gets `-d sat` unless its vid:pid is declared to
have no SMART. Canonical list, measured read-only 2026-10-09:

| Node | Targets |
|---|---|
| GPU research node | 6 SATA `sat+megaraid,{0,1,3,4,5,6}` via `/dev/bus/0` (policy `passthrough`); 2 SAS plain. The SATA drives cannot return their self-assessment on either path (controller firmware), so they read UNKNOWN / `STATUS_UNSUPPORTED`. |
| Storage host | 22 JBOD disks on the 3108 plain (SATA there returns a real self-assessment); `sdw` virtual drive explicit no-SMART; its members `megaraid,28` and `megaraid,29` via `/dev/bus/0`; 44 disks on the SAS2308 HBA plain. |
| LLM node | 7 disks on the 3008 plain; `megaraid,3` (SATA, no block device) via `/dev/bus/0`, reads `STATUS_UNSUPPORTED`; the IDSDM SD module declared no-SMART. |
| Small nodes | plain SATA + NVMe, unchanged. |

**Verdict** stays in the collector: OK only when output is complete (`end=1`) and every polled disk
returned PASSED / `SMART Health Status: OK`. FAILED is WARN. An attribute-check fallback, a status
command failure, an unopenable or unidentified device, a truncated run or an `err=` line is UNKNOWN
with a bounded reason (`STATUS_UNSUPPORTED`, `STATUS_CMD_FAILED`, `COLLECTION_FAILED`, `TRUNCATED`,
`NO_DEVICES`, `NO_VERDICT`). A disk with no SMART is listed in `metrics.no_smart`, never FAIL.

**Ordering.** Install the wrapper, the node policy and the pin on every node *before* deploying a
collector that calls it. In the other order the `smart` check reads AUTH-FAIL, never green.

`nfm-smart --targets` (root only) prints the same selection as `<device>|<type>` for the
node-exporter smartmon collector; see `smartmon-canonical/` for the proposed drop-in that removes
smartmon's duplicate `/dev/sdX` polling.
