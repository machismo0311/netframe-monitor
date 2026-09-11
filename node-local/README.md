# Node-local artifacts

Files deployed to specific nodes outside `/opt/netframe-monitor/`, tracked here for
source-of-truth. Not copied by the top-level deploy block.

| File | Deploy to | Purpose |
|---|---|---|
| `<cluster-node>-nfm-prom-health` | **`<cluster-node>`**`:/usr/local/sbin/nfm-prom-health` (root:root 0755) | Fixed, argument-less wrapper that curls Prometheus `/-/healthy` inside grafana CT 103. **CT 103 moved to <cluster-node> 2026-07-16 (AAR rec 12)** - wrapper + `monitor` sudoers pin moved with it; removed from <cluster-node>. |
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
