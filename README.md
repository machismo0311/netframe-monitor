# NetFRAME Monitor

Cluster-wide, read-only health monitor for the **km-cluster**. Runs on **Jarvis**
(`192.168.10.31`), SSHes into every other node as a low-privilege `monitor` user,
pulls diagnostics, then has Jarvis's local LLM interpret the results and publish a
web report.

> These files are the source of truth for what is deployed under
> `/opt/netframe-monitor/` on Jarvis. **Secrets and state are intentionally not in
> this repo** — see [Not included](#not-included-generated--secret).

## Components

| File | Deployed to | Role |
|---|---|---|
| `netframe_monitor.py` | `/opt/netframe-monitor/` | Collector — SSHes to each node, runs read-only checks (`df`, `journalctl -p err`, `smartctl -H -A`, `zpool`, PBS datastores, `nvidia-smi`, guest liveness via `pct list`/`qm list`, Grafana `/api/health`), parses numeric metrics, writes `last_run.json` and appends `history.jsonl`. |
| `netframe_interpret.py` | `/opt/netframe-monitor/` | Interpreter — diffs the latest run vs. previous + window trends, calls Jarvis's local **Ollama** (`localhost:11434`, `qwen2.5:7b`), writes `report.md` and renders `web/index.html`. Falls back to a deterministic report if the LLM is down. Loads standing security context from `context/*.md`. |
| `netframe-run.sh` | `/opt/netframe-monitor/` | `ExecStart` wrapper — runs the collector then the interpreter (interpreter always runs even if the collector exits non-zero). |
| `netframe-8808-lock.sh` | `/opt/netframe-monitor/` | Idempotent host-local iptables lock — restricts backend port `8808` to NPM (`192.168.10.181`) + localhost, above the tailscale chain. |
| `systemd/netframe-monitor.service` + `.timer` | `/etc/systemd/system/` | Oneshot + timer (every 15 min, `OnBootSec=3min`) that runs `netframe-run.sh`. |
| `systemd/netframe-report-web.service` | `/etc/systemd/system/` | `python -m http.server` on `0.0.0.0:8808`, `User=www-data`, rooted **only** at `web/` so keys/state are never served. |
| `systemd/netframe-8808-lock.service` | `/etc/systemd/system/` | Oneshot that applies `netframe-8808-lock.sh` on boot. |

## Access

- **Report page:** `https://health.kylemason.org` — published via nginx-proxy-manager
  (LXC 101 on pve3, `192.168.10.181`), Let's Encrypt cert, **Basic auth** enforced by
  the NPM "Homepage Auth" access list. The Cloudflare `health` A record is DNS-only and
  points at a private IP, so the page is reachable over the Headscale tailnet, not the
  public internet.
- Direct access to `http://192.168.10.31:8808/` is dropped for everything except NPM +
  localhost, so the unauthenticated backend cannot be reached directly.

## Monitoring-CT / service checks (Tier 1 + 2)

Beyond host health, the collector tracks the **observability stack**:

- **Guest liveness (Tier 1)** — from the PVE host, `sudo -n pct list` (pve3 LXCs:
  grafana, homepage, headscale…) and `sudo -n qm list` (QuarkyLab: wazuh VM). A check
  goes `WARN` if any guest named in `MONITORING_GUESTS` (grafana, wazuh, prometheus,
  loki, homepage, pihole, uptime-kuma) is not `running`.
- **Service health (Tier 2)** — Grafana `/api/health` probed from Jarvis over the
  network (`WARN` if unreachable or DB not `ok`).
- **Service-internal health (Tier 3)** — the observability stack in the grafana CT
  and Pi-hole:
  - **Loki** — buildinfo probed from Jarvis (network; `0.0.0.0:3100`). Stable up-signal.
  - **Prometheus** — `127.0.0.1:9090` inside CT 103 (pentest **F-03**), so probed from
    *inside* the CT via a fixed root-owned wrapper `/usr/local/sbin/nfm-prom-health`
    (sudoers-pinned; the monitor cannot pass arguments). No localhost binding is relaxed.
  - **Pi-hole** (LXC on the standalone Mac Mini `pve1`, not a cluster member) — probed by
    its actual function: a DNS answer + admin HTTP `200`, from Jarvis. No host access needed.
  - **Wazuh** (SIEM, VM 104 on QuarkyLab, own IP `192.168.10.184`) — `wazuh-control status`
    over SSH as the `monitor` user (scoped sudo). Verdict keys off the **core** daemons
    (analysisd, remoted, db, modulesd, syscheckd); optional daemons (clusterd, maild,
    agentlessd, integratord, dbd, csyslogd) are down by design, and `wazuh-control` exits
    non-zero regardless, so **rc is ignored**. Plus unprivileged `df` for SIEM disk.
- **Self-guard** — `page_auth` curls `https://health.kylemason.org` from Jarvis with no
  credentials: **`401` = auth enforced (OK)**, **`200` = the NPM access list got detached
  and the page is public (WARN)**. Catches the recurring reset described under *Access*.

**Per-node sudoers** (`/etc/sudoers.d/monitor`) is scoped to exact commands — never
blanket `pct`/`qm`, which could start/stop/destroy guests:

| Node | `monitor` NOPASSWD entries |
|---|---|
| pve3 | `journalctl`, `smartctl`, **`pct list`**, **`/usr/local/sbin/nfm-prom-health`** |
| QuarkyLab | `journalctl`, `smartctl`, `zpool`, **`qm list`** |
| randy | `journalctl`, `smartctl`, `zpool`, `proxmox-backup-manager` |
| **wazuh VM (.184)** | **`/var/ossec/bin/wazuh-control status`** (df runs unprivileged) |
| pve2/pve4/pve5 | `journalctl`, `smartctl` |

> **`/usr/local/sbin/nfm-prom-health`** is a fixed root-owned wrapper deployed on pve3
> (not in this repo's deploy list above — it lives at `/usr/local/sbin/`): it runs exactly
> `pct exec 103 -- curl -s -m 3 http://localhost:9090/-/healthy` and accepts no arguments.
>
> **NPM access-list resets:** editing the `health.kylemason.org` proxy host and saving
> without re-selecting **Access List = "Homepage Auth"** and **Force SSL** silently reverts
> it to *Publicly Accessible*. The `page_auth` guard exists to catch this; re-attach both in
> the NPM UI when it WARNs.

## Deploy / update

```bash
# from this directory, on a host with ssh access to jarvis
scp netframe_monitor.py netframe_interpret.py netframe-run.sh netframe-8808-lock.sh \
    jarvis:/opt/netframe-monitor/
scp systemd/*.service systemd/*.timer jarvis:/etc/systemd/system/
ssh jarvis 'chmod +x /opt/netframe-monitor/*.sh && systemctl daemon-reload \
    && systemctl enable --now netframe-monitor.timer netframe-report-web.service netframe-8808-lock.service'
```

Check it:

```bash
ssh jarvis 'systemctl start netframe-monitor.service && cat /opt/netframe-monitor/report.md'
```

## Not included (generated / secret)

Kept on Jarvis only, never committed:

- `monitor_key`, `monitor_key.pub` — the `monitor` SSH keypair.
- `last_run.json`, `history.jsonl`, `report.md`, `reports/` — runtime state and output.
- `web/` — the rendered page (regenerated every run).
- `context/*.md` — standing security context (e.g. the pentest tracker) fed to the
  interpreter; sourced from the vault, not duplicated here.
