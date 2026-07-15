# Node-local artifacts

Files deployed to specific nodes outside `/opt/netframe-monitor/`, tracked here for
source-of-truth. Not copied by the top-level deploy block.

| File | Deploy to | Purpose |
|---|---|---|
| `pve3-nfm-prom-health` | `pve3:/usr/local/sbin/nfm-prom-health` (root:root 0755) | Fixed, argument-less wrapper that curls Prometheus `/-/healthy` inside grafana CT 103. Referenced by the `monitor` sudoers entry on pve3. |

## quarkylab-nfm-wazuh-indexer-restart
Deployed to `quarkylab:/usr/local/sbin/nfm-wazuh-indexer-restart` (root:root 755).
The ONLY action the `monitor` user can take on QuarkyLab beyond read-only checks:
the EVT-004 in-place wazuh-indexer restart inside VM 104 via the guest agent
(never a power-cycle). Sudoers pin (in `/etc/sudoers.d/monitor`, note the `""` =
no arguments permitted):

    monitor ALL=(root) NOPASSWD: /usr/local/sbin/nfm-wazuh-indexer-restart ""

Invoked by `netframe_remediate.py` action `restart-wazuh-indexer` after explicit
human approval. Live-fire validated 2026-07-15 (indexer returned to active).
