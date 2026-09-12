#!/usr/bin/env bash
# NetFRAME operational-memory backup (JAR-01). Encrypted restic to Randy over the
# VLAN30 data path: /opt/netframe-monitor (context/, ledgers, baselines, history,
# reports, keys) plus the netframe systemd units. Retention: 14 daily, 8 weekly.
#
# ALSO COVERS llm_router (added 2026-09-12). Jarvis is a PVE *host*, so PBS backs up
# its guests and not its own filesystem, and this job was the only thing backing up
# anything under /opt. llm_router is tier-1 - it serves the :8000 endpoint Open WebUI,
# the operations console and Jarvis On-Call all depend on - and until now a Jarvis disk
# loss would have taken it with no copy anywhere. Its tracked source in Home-Lab is a
# reference, not a backup: it carries no venv, no RAG corpus and no secret.
#
# What is deliberately excluded, and why:
#   venv/         rebuildable from requirements.txt, which is now correct on the host
#                 (it was missing numpy until 2026-09-12, so a rebuild would have
#                 produced a host where the RAG path could not import). Restoring the
#                 venv means `python3 -m venv venv && venv/bin/pip install -r
#                 requirements.txt`, not a file restore. See the restore note below.
#   __pycache__   bytecode, already covered by the pattern exclude below.
# What is deliberately INCLUDED even though it looks derived:
#   rag_docs/, rag_embeddings.npy, rag_index.json  (~2MB total)
#                 the RAG corpus and its embeddings. These are NOT bit-reproducible:
#                 rag_ingest.py rebuilds them from the Home-Lab vault, which moves, and
#                 the embeddings come from a model (nomic-embed-text) via Ollama. Cheap
#                 to store, expensive and non-identical to regenerate, so they are state.
#   /etc/llm_router.env  0600 root:root. This repository already carries 0600 material
#                 (monitor_key, github_token under /opt/netframe-monitor), so including
#                 it follows the established model rather than inventing a new one. The
#                 repo is encrypted and its password is 0600 on Jarvis and in Vaultwarden.
# The restic password lives in /root/.config/restic/netframe-pass (0600) and MUST
# also be filed in Vaultwarden, or a Jarvis disk loss makes the repo unreadable.
# Restore example:
#   restic -r sftp:root@192.168.30.187:/mnt/bulk/backups/jarvis-netframe \
#     --password-file /root/.config/restic/netframe-pass restore latest --target /
# After an llm_router restore the venv is NOT in the snapshot; recreate it before start:
#   python3 -m venv /opt/llm_router/venv
#   /opt/llm_router/venv/bin/pip install -r /opt/llm_router/requirements.txt
#   systemctl daemon-reload && systemctl start llm-router-lock llm_router
export RESTIC_REPOSITORY=sftp:root@192.168.30.187:/mnt/bulk/backups/jarvis-netframe
export RESTIC_PASSWORD_FILE=/root/.config/restic/netframe-pass

restic backup /opt/netframe-monitor /etc/systemd/system/netframe-* \
	/opt/llm_router /etc/llm_router.env \
	/etc/systemd/system/llm_router.service /etc/systemd/system/llm-router-lock.service \
	--exclude /opt/netframe-monitor/web \
	--exclude "__pycache__" \
	--exclude /opt/llm_router/venv \
	--tag netframe
rc=$?
restic forget --keep-daily 14 --keep-weekly 8 --prune --quiet || true
# Freshness marker for backup-verify style checks: age of the newest snapshot.
restic snapshots --latest 1 --json > /opt/netframe-monitor/context/backup-last-snapshot.json 2>/dev/null || true
exit "$rc"
