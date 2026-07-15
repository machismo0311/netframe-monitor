# Jarvis Disaster Recovery Runbook

**Scope:** rebuild the Jarvis AI-operations plane after total loss of the host
(`192.168.10.31`, mgmt / `192.168.30.31`, VLAN30 data). This is the operational plane
only. The estate it watches (the km-cluster, Randy, QuarkyLab) recovers by its own
procedures and is unaffected by Jarvis being down.

> Read this from GitHub if Jarvis is gone. It is intentionally in the public-structure repo
> so it is reachable from any device during an outage. No secrets are in this file.

## RTO / RPO

- **RPO (data loss):** at most 24h (nightly backup at 04:30). Operational memory changes
  slowly, so real loss is usually less.
- **RTO (time to restore):** 2 to 3 hours. The long pole is re-pulling the Ollama models
  (~52GB, dominated by the 47GB 72B), not the restore itself (~minutes).

## The one hard dependency

The restic repo on Randy is encrypted. Its passphrase lives at
`/root/.config/restic/netframe-pass` on Jarvis **and must also be in Vaultwarden**
(item: "Jarvis restic backup passphrase"). If Jarvis is lost and the passphrase is not in
Vaultwarden, **the backup is permanently unreadable.** Verify the Vaultwarden copy exists
*before* you ever need it.

To file it (run in your own shell, so the master password and the secret never transit a
tool or an assistant):

```bash
BW_SESSION=$(bw unlock --raw)                                   # prompts for master password
PASS=$(ssh jarvis 'cat /root/.config/restic/netframe-pass')
printf '{"type":2,"name":"Jarvis restic backup passphrase","notes":"%s","secureNote":{"type":0}}' "$PASS" \
  | bw encode | bw create item --session "$BW_SESSION"
bw sync --session "$BW_SESSION"
```

## What is in the backup vs what must be rebuilt

| In the restic backup (restored) | NOT in the backup (rebuild / re-pull) |
|---|---|
| `/opt/netframe-monitor` (code, `context/`, ledgers, baselines, `history.jsonl`, `monitor_key`) | Ollama models (qwen2.5:72b, :7b, nomic-embed-text) |
| All `netframe-*` systemd unit files | The OS, restic, ollama, node-exporter packages |
| Reports archive | node-exporter textfile scrape (default dir works out of the box) |
| The restic passphrase (excluded by design; from Vaultwarden) | Per-node `monitor` sudoers (already on the nodes, not on Jarvis) |

## Rebuild procedure

### 1. Provision the host
- Debian 13 (trixie), hostname `Jarvis`, static `192.168.10.31/24` + VLAN30 `192.168.30.31/24`.
- Packages: `apt-get install -y restic prometheus-node-exporter prometheus-node-exporter-collectors`
- Install Ollama (`curl -fsSL https://ollama.com/install.sh | sh`), `systemctl enable --now ollama`.

### 2. Restore operational state from Randy
```bash
mkdir -p /root/.config/restic
# put the passphrase from Vaultwarden into this file:
printf '%s' '<PASSPHRASE FROM VAULTWARDEN>' > /root/.config/restic/netframe-pass
chmod 600 /root/.config/restic/netframe-pass
export RESTIC_REPOSITORY=sftp:root@192.168.30.187:/mnt/bulk/backups/jarvis-netframe
export RESTIC_PASSWORD_FILE=/root/.config/restic/netframe-pass
restic snapshots                     # confirm you can read the repo (proves the passphrase)
restic restore latest --target /     # restores /opt/netframe-monitor + /etc/systemd/system/netframe-*
chmod 600 /opt/netframe-monitor/monitor_key
```
Randy must be reachable on VLAN30 (`192.168.30.187`) and trust Jarvis's root key (cluster
peer trust; accept the host key on first connect).

### 3. Re-pull the models
```bash
ollama pull qwen2.5:7b
ollama pull nomic-embed-text
ollama pull qwen2.5:72b              # ~47GB, the long pole
```

### 4. Re-enable the timers and web
```bash
systemctl daemon-reload
for t in monitor daily confdrift predict monthly ghreview backup; do
  systemctl enable --now "netframe-$t.timer"
done
systemctl enable --now netframe-report-web.service
systemctl enable --now netframe-8808-lock.service     # iptables guard on :8808
```

### 5. Restore the GitHub token (optional, for private-repo review)
Place the fine-grained read-only PAT at `/opt/netframe-monitor/github_token` (chmod 600)
from Vaultwarden. Without it the GitHub review degrades to public-only and says so.

## Validation (do not declare recovered until all pass)

```bash
# 1. read the repo (proves passphrase + Randy path)
restic snapshots | tail -3
# 2. a full monitor cycle succeeds
bash /opt/netframe-monitor/netframe-run.sh; echo "rc=$?"
# 3. dashboard + health page serve
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8808/index.html
# 4. heartbeat metric present (the dead-man's source)
curl -s localhost:9100/metrics | grep netframe_last_run_timestamp_seconds
# 5. models answer
ollama run qwen2.5:7b 'reply OK' | head -1
# 6. a fresh backup writes
systemctl start netframe-backup.service && systemctl show netframe-backup.service -p Result
# 7. the ledger and known events restored
python3 /opt/netframe-monitor/netframe_remediate.py history -n 5
ls /opt/netframe-monitor/context/30-known-events.md
```

When all seven pass, the dead-man alert (`NetframeMonitorStale`) will clear on the next
Grafana evaluation, which is the external confirmation that Jarvis is back.

## Recovery dependency summary

| Dependency | Where | If missing |
|---|---|---|
| restic passphrase | Vaultwarden (+ Jarvis 600 file) | **backup unreadable, recovery impossible** |
| restic repo | Randy `bulk/backups/jarvis-netframe` | no restore point |
| Randy reachable | VLAN30 `.30.187` | cannot restore until Randy is up |
| Ollama models | re-pullable from ollama.com | reasoning degraded until pulled |
| GitHub PAT | Vaultwarden | GitHub review public-only |
