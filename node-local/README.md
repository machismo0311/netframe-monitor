# Node-local artifacts

Files deployed to specific nodes outside `/opt/netframe-monitor/`, tracked here for
source-of-truth. Not copied by the top-level deploy block.

| File | Deploy to | Purpose |
|---|---|---|
| `pve3-nfm-prom-health` | `pve3:/usr/local/sbin/nfm-prom-health` (root:root 0755) | Fixed, argument-less wrapper that curls Prometheus `/-/healthy` inside grafana CT 103. Referenced by the `monitor` sudoers entry on pve3. |
