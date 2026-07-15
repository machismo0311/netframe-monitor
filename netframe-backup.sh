#!/usr/bin/env bash
# NetFRAME operational-memory backup (JAR-01). Encrypted restic to Randy over the
# VLAN30 data path: /opt/netframe-monitor (context/, ledgers, baselines, history,
# reports, keys) plus the netframe systemd units. Retention: 14 daily, 8 weekly.
# The restic password lives in /root/.config/restic/netframe-pass (0600) and MUST
# also be filed in Vaultwarden, or a Jarvis disk loss makes the repo unreadable.
# Restore example:
#   restic -r sftp:root@192.168.30.187:/mnt/bulk/backups/jarvis-netframe \
#     --password-file /root/.config/restic/netframe-pass restore latest --target /
export RESTIC_REPOSITORY=sftp:root@192.168.30.187:/mnt/bulk/backups/jarvis-netframe
export RESTIC_PASSWORD_FILE=/root/.config/restic/netframe-pass

restic backup /opt/netframe-monitor /etc/systemd/system/netframe-* \
	--exclude /opt/netframe-monitor/web \
	--exclude "__pycache__" \
	--tag netframe
rc=$?
restic forget --keep-daily 14 --keep-weekly 8 --prune --quiet || true
# Freshness marker for backup-verify style checks: age of the newest snapshot.
restic snapshots --latest 1 --json > /opt/netframe-monitor/context/backup-last-snapshot.json 2>/dev/null || true
exit "$rc"
