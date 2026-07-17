# Node-local artifacts

Files deployed to specific nodes outside `/opt/netframe-monitor/`, tracked here for
source-of-truth. Not copied by the top-level deploy block.

| File | Deploy to | Purpose |
|---|---|---|
| `pve3-nfm-prom-health` | **`pve4`**`:/usr/local/sbin/nfm-prom-health` (root:root 0755) | Fixed, argument-less wrapper that curls Prometheus `/-/healthy` inside grafana CT 103. **CT 103 moved to pve4 2026-07-16 (AAR rec 12)** - wrapper + `monitor` sudoers pin moved with it; removed from pve3. |
| `pve3-nfm-npm-dns-audit` | `pve3:/usr/local/sbin/nfm-npm-dns-audit` (root:root 0755) | Argument-free wrapper that enumerates NPM proxy-host `server_name`s (from the LXC-101 bind mount, no admin API/password) and resolves each against the primary Pi-hole (`.177`), emitting `name=OK\|MISSING` + a `total=/missing=` summary. Catches the 2026-07-15 failure class: a published NPM host with no Pi-hole local record (rebind-stripped, unresolvable LAN-wide). Feeds the `npm_dns` check on the pve3 node. Sudoers pin (note the `""` = no args): `monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-npm-dns-audit ""`. Emits only hostnames + status, no secrets. |
| `jarvis-nfm-llm-router-conformance` | `jarvis:/usr/local/sbin/nfm-llm-router-conformance` (root:root 0755) | NF-AIOPS-004 Phase 3. Argument-free conformance wrapper for llm_router. Reports **config / runtime / firewall as three separate dimensions** (never one boolean), emitting only booleans + non-secret expected/actual tokens - never file contents, env values, or secrets. On Jarvis the collector runs locally **as root** (llm_router is Jarvis's own service), so it invokes the wrapper directly with **no sudoers pin**; the wrapper stays root-owned/arg-free/Git-tracked so extending it to a remote node drops straight into the standard `monitor` + `""`-no-args sudoers pattern. Observe-only: a drift becomes a screened recommendation through the existing gated path; it never edits config, restarts, or touches the firewall. |

## quarkylab-nfm-wazuh-indexer-restart
Deployed to `quarkylab:/usr/local/sbin/nfm-wazuh-indexer-restart` (root:root 755).
The ONLY action the `monitor` user can take on QuarkyLab beyond read-only checks:
the EVT-004 in-place wazuh-indexer restart inside VM 104 via the guest agent
(never a power-cycle). Sudoers pin (in `/etc/sudoers.d/monitor`, note the `""` =
no arguments permitted):

    monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-wazuh-indexer-restart ""

Invoked by `netframe_remediate.py` action `restart-wazuh-indexer` after explicit
human approval. Live-fire validated 2026-07-15 (indexer returned to active).
