#!/usr/bin/env python3
"""NetFRAME cluster health monitor.

Runs on Jarvis. SSHes into every other cluster node as the low-privilege
`monitor` user and pulls read-only diagnostics (disk usage, recent journal
errors, SMART health, ZFS pool status, PBS datastores, GPU status). The
local Jarvis host is checked directly (no SSH).

All privileged commands go through a tightly scoped NOPASSWD sudoers entry
on each node (see /etc/sudoers.d/monitor); df and nvidia-smi run unprivileged.

Outputs (all under /opt/netframe-monitor/):
  - stdout               -> captured by systemd/journald (full per-check text)
  - last_run.json        -> enriched snapshot (verdict, rc, parsed metrics,
                            truncated raw excerpt) — consumed by the interpreter
  - history.jsonl        -> one compact metrics line per run (capped), for trends

The companion netframe_interpret.py reads last_run.json + history.jsonl and
has Jarvis's local LLM write report.md.
"""

import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

# Sibling modules live next to this file both in the repository and in /opt/netframe-monitor.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import netframe_wazuh_health as WH  # noqa: E402
import netframe_guest_state as GS  # noqa: E402

BASE = "/opt/netframe-monitor"
KEY = f"{BASE}/monitor_key"
STATE_FILE = f"{BASE}/last_run.json"
HISTORY_FILE = f"{BASE}/history.jsonl"
HISTORY_CAP = 3400  # ~35 days at the 15-min cadence, so the 14d predict and 30d
                    # monthly windows are actually populated; a few MB at most

CHECK_TIMEOUT = 120  # Randy's SMART sweep over 50+ SAS disks is the slow path
RAW_EXCERPT = 1200   # chars of raw output kept per check in last_run.json

# Prometheus textfile export. The collector already owns the semantics of every check, so the
# normalized verdict is exported once, here, and Prometheus consumes THAT. Making Prometheus
# re-parse backup-report.json / hardening-drift.json / restore-verify.json would duplicate the
# parsers and let the two drift apart, which is the failure this avoids.
#
# Same directory netframe-run.sh already writes netframe.prom into, read by the node_exporter
# textfile collector on this host. A separate FILE, not a separate pipeline: netframe.prom marks
# the end of a whole netframe-run cycle, while this marks the end of a COLLECTOR pass, and the two
# are written by different programs at different moments.
TEXTFILE_DIR = "/var/lib/prometheus/node-exporter"
TEXTFILE_NAME = "netframe_checks.prom"

# Bounded by construction. `reason` may only ever be one of a small fixed vocabulary or empty, so
# a label can never carry a free-form error string or an unbounded value.
REASON_ABSENT, REASON_STALE = "ABSENT", "STALE"
_REASON_MAX = 32

# ---------------------------------------------------------------------------
# Read-only diagnostic commands. Privileged ones use the full binary path and
# are matched by /etc/sudoers.d/monitor on each node.
# ---------------------------------------------------------------------------
DF = "/usr/bin/df -h -x tmpfs -x devtmpfs -x overlay -x squashfs"
JOURNAL = "sudo -n /usr/bin/journalctl -p err -b --since '-20min' --no-pager"
# TIME-bounded, not count-bounded: "-b -n 25" let a single non-recurring event (e.g. one
# auth failure) sit in the last-25-since-boot window and re-report as freshly active on
# every run until 25 newer err lines or a reboot pushed it out (measured: 22h+ on Randy,
# 2026-09-25 dashboard reconciliation). 20min gives headroom over the monitor's own 15min
# cadence (netframe-monitor.timer OnUnitActiveSec) so a one-off ages out within one cycle.
# Sudoers on every node matches this EXACT argv (see /etc/sudoers.d/monitor) - changing it
# here requires updating all seven sudoers files in the same change.
# -H (health verdict) + -A (attributes) so we can trend pending/realloc/temp.
SMART = (
    "for d in $(lsblk -dno NAME,TYPE | awk '$2==\"disk\"{print $1}'); do "
    "echo \"== /dev/$d ==\"; sudo -n /usr/sbin/smartctl -H -A /dev/$d 2>&1; done"
)
ZPOOL = "sudo -n /usr/sbin/zpool status -x; echo '---'; sudo -n /usr/sbin/zpool list"
PBS = "sudo -n /usr/sbin/proxmox-backup-manager datastore list"
# Backup-verify report emitted by the Ansible backup-verify playbook (daily cron
# on Ares, written world-readable on Randy). Unprivileged cat — freshness is
# judged from the report's own `generated_epoch`, so a dead cron/timer surfaces
# as a stale report (WARN) instead of silently going unnoticed.
BACKUP_VERIFY = "cat /var/log/netframe-monitor/backup-report.json 2>/dev/null"
BACKUP_VERIFY_MAX_AGE_H = 26  # written ~06:00 daily; older => stale
# Hardening drift report (world-readable JSON emitted by the daily Ares drift-check that
# runs the hardening role in --check mode). Unprivileged cat, same pattern as backup_verify.
HARDENING_DRIFT = "cat /var/log/netframe-monitor/hardening-drift.json 2>/dev/null"
HARDENING_DRIFT_MAX_AGE_H = 30  # daily cron; older => stale (dead cron / control node down)
# Restore-verify evidence from the monthly Ares restic restore drill, published to Randy by
# playbooks/scheduling/publish-restore-evidence.sh. Same unprivileged-cat pattern as the two above.
RESTORE_VERIFY = "cat /var/log/netframe-monitor/restore-verify.json 2>/dev/null"
# Derived from the drill's ACTUAL cadence rather than picked. The timer is OnCalendar=monthly with
# RandomizedDelaySec=1h, so the longest legitimate gap between two runs is the longest month plus
# the jitter (31d + 1h). The remaining 24h is grace for execution time, one monitor collection
# cycle, and a brief control-node outage across a month boundary. A monthly drill must NOT read as
# stale merely because 30 days passed and the next scheduled run has not come round yet.
RESTORE_VERIFY_MAX_AGE_H = 31 * 24 + 1 + 24  # 769h
GPU = (
    "/usr/bin/nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,"
    "memory.used,memory.total --format=csv,noheader,nounits"
)
# Guest (CT/VM) liveness, read-only. Scoped in sudoers to the `list` subcommand
# only — NOT blanket pct/qm (which could start/stop/destroy). pct on pve3 (LXCs:
# grafana/homepage/etc.), qm on QuarkyLab (wazuh VM).
PCT_LIST = "sudo -n /usr/sbin/pct list"
QM_LIST = "sudo -n /usr/sbin/qm list"
# Guest state by VMID, read from PVE's API (pvesh) by the generic argument-free wrapper
# node-local/pve-nfm-guests, installed as /usr/local/sbin/nfm-guests. Unlike `guests` above it can
# see a PAUSED VM (qmpstatus), carries collected_at, reads onboot from PVE's own config, and is judged
# against a tracked inventory keyed by VMID; netframe_guest_state classifies it. A NEW check name on
# purpose: the live wall merges checks["guests"]["metrics"]["guests"] and paints a running guest
# green, so data under `guest_state` can never turn an application tile green. Guest RUNNING is
# infrastructure context only, never application health. pve5 only for now; the other nodes keep
# `guests` until they are migrated. The inventory keeps its node-local/ path when deployed.
GUEST_STATE = "sudo -n /usr/local/sbin/nfm-guests"
GUEST_INVENTORY = os.path.join(_HERE, "node-local", "pve-expected-guests.psv")
# Monitoring-service health, probed from Jarvis over the network. Grafana's
# /api/health is unauthenticated and reports its DB status. Grafana fronts
# Prometheus/Loki, which stay localhost-bound (pentest F-03) and so are only
# reachable from inside their CT — deliberately out of scope here.
GRAFANA = "/usr/bin/curl -fsS -m 5 http://192.168.10.183:3000/api/health"

# Guests whose being down is worth an alert (the observability/monitoring stack).
MONITORING_GUESTS = {"grafana", "wazuh", "prometheus", "loki",
                     "homepage", "pihole", "pi-hole", "uptime-kuma"}

# --- Tier 3: service-internal / in-stack health -----------------------------
# Prometheus is 127.0.0.1-bound inside the grafana CT (pentest F-03), so it is
# probed from *inside* CT 103 via a fixed, root-owned, sudoers-pinned wrapper
# (/usr/local/sbin/nfm-prom-health) — the monitor cannot pass it any arguments.
PROMETHEUS = "sudo -n /usr/local/sbin/nfm-prom-health"
# UPS health via pve3's NUT daemon (LAN-listening :3493), polled from Jarvis with
# nut-client so UPS state is visible in every report and the loss of UPS monitoring
# itself surfaces as a WARN instead of dying silently with its host (AAR 2026-07-16
# recommendation 14). Both UPSes: tripplite (USB) + midatlantic (SNMP).
UPS = ("for u in tripplite midatlantic; do echo \"== $u ==\"; "
       "/usr/bin/upsc $u@192.168.10.201 2>&1 "
       "| grep -E 'ups.status|battery.charge:|battery.runtime:'; done")
# NPM-vs-Pi-hole DNS audit (runs on pve3, where NPM lives). Enumerates NPM proxy-host
# server_names and resolves each against the primary Pi-hole - catches a published host
# with no local DNS record (rebind-stripped -> unresolvable LAN-wide, the 2026-07-15 gap).
# Arg-free root-owned wrapper; emits only hostnames + OK/MISSING.
NPM_DNS = "sudo -n /usr/local/sbin/nfm-npm-dns-audit"
# Loki is network-reachable; buildinfo is a stable up-signal (avoids /ready 503 flap).
LOKI = "/usr/bin/curl -fsS -m 5 http://192.168.10.183:3100/loki/api/v1/status/buildinfo"
# DETECT-01: network-device (OPNsense/EX3400) event signals from Loki (read-only).
# net_config_change = firewall/switch commit/reconfigure events in the last hour (info,
# does not alarm; the interpreter reasons about "did the config change?"). net_syslog_flow =
# total network-syslog volume in 15m (dead-man: WARN if it dries up = logging stopped).
_LOKI_Q = "http://192.168.10.183:3100/loki/api/v1/query"
NET_CFGCHG = ("/usr/bin/curl -fsS -m 6 -G " + _LOKI_Q + " --data-urlencode "
              "'query=sum(count_over_time({job=\"network-syslog\"} "
              "|~ \"(?i)commit complete|reconfigure\" [1h]))'")
NET_FLOW = ("/usr/bin/curl -fsS -m 6 -G " + _LOKI_Q + " --data-urlencode "
            "'query=sum(count_over_time({job=\"network-syslog\"} [15m]))'")
# Pi-hole (LXC on the standalone Mac Mini pve1, not a cluster member): probed by its
# actual function — a DNS answer + admin HTTP — from Jarvis, no host access needed.
PIHOLE = ("echo DNS:; dig +short +time=3 +tries=1 @192.168.10.177 example.com A; "
          "echo HTTP:; /usr/bin/curl -s -o /dev/null -w '%{http_code}' -m 5 "
          "http://192.168.10.177/admin/")
# Wazuh SIEM (VM 104 on QuarkyLab, its own IP .184). Packet C: the old check ran only
# `wazuh-control status` and its answer was shown as the health of the whole SIEM, which read
# "CORE OK" in green for eight days with the indexer down and auth telemetry blind on 8 of 9 hosts.
# The argument-free, root-owned wrapper (node-local/azuh-nfm-wazuh-health) reports seven measured
# inputs; netframe_wazuh_health classifies them. The tracked expected-agents list sits next to this
# file. ONE ssh call feeds two checks: `wazuh` (services: manager, indexer, dashboard, Filebeat) and
# the derived `wazuh_coverage` (integrity: agents, auth telemetry, drops).
WAZUH_HEALTH = "sudo -n /usr/local/sbin/nfm-wazuh-health"
WAZUH_EXPECTED_AGENTS = os.path.join(_HERE, "wazuh-expected-agents.psv")
# Self-guard: the report page must stay behind NPM Basic auth. An un-credentialed
# request should get 401; a 200 means the NPM access list got detached (the page is
# publicly readable) — WARN so we notice instead of it silently regressing.
AUTHGUARD = ("echo -n 'health.kylemason.org (auth-gated) HTTP '; "
             "/usr/bin/curl -s -o /dev/null -w '%{http_code}\\n' -m 8 "
             "https://health.kylemason.org")
# Same self-guard for the operations console. It is a SEPARATE NPM proxy host, so
# its access list can detach independently of health's — and a public console is
# worse than a public report page, since it exposes the chat interface.
CONSOLE_AUTHGUARD = ("echo -n 'console.kylemason.org (auth-gated) HTTP '; "
                     "/usr/bin/curl -s -o /dev/null -w '%{http_code}\\n' -m 8 "
                     "https://console.kylemason.org")
# llm_router (Jarvis :8000) serves Open WebUI, which lives on another host. Probe it
# through NPM — the path a real consumer takes — NOT via localhost. On 2026-07-14 its
# bind regressed to 127.0.0.1: the service stayed "active", localhost still answered
# 200, and Open WebUI was quietly broken for a day. A localhost probe would have
# reported healthy throughout. This exercises DNS + NPM + the bind + the :8000
# allowlist in one shot.
LLM_ROUTER = ("echo -n 'llm.netframe.local (llm_router via NPM) HTTP '; "
              "/usr/bin/curl -s -o /dev/null -w '%{http_code}\\n' -m 8 "
              "http://llm.netframe.local/v1/models")
# --- User-journey tiers (NF-AIOPS-004 Phase 2) -------------------------------------
# The auth guards above are AUTHENTICATE probes, not REACH probes, and the distinction is
# not academic: NPM applies auth_basic in nginx's access phase, before proxy_pass in the
# content phase, so an un-credentialed request returns 401 without the upstream ever being
# contacted. page_auth/console_auth therefore stay green with a dead backend. These probes
# close that gap by proving the backend actually serves.
CONSOLE_BACKEND = ("echo -n 'console backend api/overview HTTP '; "
                   "/usr/bin/curl -s -o /dev/null -w '%{http_code}\\n' -m 8 "
                   "http://127.0.0.1:8809/api/overview")
REPORT_BACKEND = ("echo -n 'report page backend HTTP '; "
                  "/usr/bin/curl -s -o /dev/null -w '%{http_code}\\n' -m 8 "
                  "http://127.0.0.1:8808/")
OPENWEBUI_REACH = ("echo -n 'chat.netframe.local (Open WebUI via NPM) HTTP '; "
                   "/usr/bin/curl -s -o /dev/null -w '%{http_code}\\n' -m 8 "
                   "http://chat.netframe.local/")
# Transact: one real user action. Admission-controlled, fast model only, hourly at most.
# Emits its own key=value line; SKIPPED when conditions are insufficient (never WARN).
CONSOLE_TRANSACT = f"/usr/bin/python3 {BASE}/netframe_transact.py console"
# Narrow conformance for llm_router (NF-AIOPS-004 Phase 3): the root-owned, arg-free
# wrapper reports config/runtime/firewall as three SEPARATE dimensions. Emits only
# booleans + non-secret expected/actual tokens; never file contents or secrets. This is
# Jarvis's OWN service and the collector runs locally as root here (no monitor-user SSH
# hop, unlike other nodes), so the wrapper is invoked directly. The root-owned 0755
# wrapper is still the reviewed, Git-tracked, arg-free artifact; being root itself, the
# collector needs no sudoers pin for it on this host.
LLM_ROUTER_CONFORMANCE = "/usr/local/sbin/nfm-llm-router-conformance"
# Dual-WAN failover posture, read from OPNsense (VM 100) on pve2 through the same root-owned,
# argument-free, sudoers-pinned wrapper pattern as nfm-prom-health. The wall dashboard must be able
# to state "failover is armed" and "traffic is on WAN1" without inferring either, and neither fact
# is reachable from the wall Pi: both live inside the OPNsense guest, and the Pi deliberately holds
# no pve2 access and no OPNsense credential. Deriving it here publishes it through last_run.json,
# which the Pi already reads over its existing forced command, so the wall gains the fact and gains
# no privilege. Emits only a bounded key=value vocabulary.
WAN_POSTURE = "sudo -n /usr/local/sbin/nfm-wan-posture"

# Verdict severity. SKIPPED ranks at 0 alongside OK deliberately: an untested service must
# never make the estate look unhealthy, so a skip cannot raise the overall verdict. It is
# surfaced separately as "NOT TESTED" rather than folded in, so it also cannot be mistaken
# for a passing test. Module-level so the ordering is testable rather than buried in main().
#
# CRIT and UNKNOWN came with Packet C (the Wazuh health checks). UNKNOWN ranks with WARN, above OK,
# so an unmeasured check can never make the estate read healthy; CRIT ranks with the hard failures.
# A verdict missing from this table ranks as a hard failure too (see VERDICT_RANK_DEFAULT): a new
# verdict must never crash the sweep with a KeyError, and must never be read as OK.
VERDICT_RANK = {"OK": 0, "SKIPPED": 0, "WARN": 1, "UNKNOWN": 1, "CRIT": 2, "AUTH-FAIL": 2,
                "TIMEOUT": 2, "UNREACHABLE": 2}
VERDICT_RANK_DEFAULT = 2

NODES = {
    "jarvis":    {"ip": None,             "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "gpu": GPU, "llm_router_conformance": LLM_ROUTER_CONFORMANCE}},
    "randy":     {"ip": "192.168.10.187", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "zpool": ZPOOL, "pbs": PBS, "backup_verify": BACKUP_VERIFY, "hardening_drift": HARDENING_DRIFT, "restore_verify": RESTORE_VERIFY}},
    "quarkylab": {"ip": "192.168.10.179", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "zpool": ZPOOL, "gpu": GPU, "guests": QM_LIST}},
    "pve2":      {"ip": "192.168.10.204", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART,
                                                 # OPNsense (VM 100) lives here, so the dual-WAN posture is read here.
                                                 "wan_failover": WAN_POSTURE}},
    # prometheus check rides with CT 103, which moved to pve4 2026-07-16 (AAR rec 12:
    # alerting no longer shares a node with NPM/Vaultwarden); npm_dns stays with NPM on pve3.
    "pve3":      {"ip": "192.168.10.201", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "guests": PCT_LIST, "npm_dns": NPM_DNS}},
    "pve4":      {"ip": "192.168.10.202", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "guests": PCT_LIST, "prometheus": PROMETHEUS}},
    # guest_state, never `guests`: see GUEST_STATE for why pve5 must not emit the legacy check.
    "pve5":      {"ip": "192.168.10.203", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "guest_state": GUEST_STATE}},
    # Wazuh SIEM VM (.184): seven-input health via the argument-free wrapper (scoped sudo), which
    # also yields the derived wazuh_coverage check, plus unprivileged df.
    "wazuh":     {"ip": "192.168.10.184", "checks": {"wazuh": WAZUH_HEALTH, "df": DF}},
    # Synthetic node: monitoring-service health probed locally from Jarvis (no SSH).
    "monitoring": {"ip": None,            "checks": {"grafana": GRAFANA, "loki": LOKI, "pihole": PIHOLE, "page_auth": AUTHGUARD, "console_auth": CONSOLE_AUTHGUARD, "llm_router": LLM_ROUTER, "console_backend": CONSOLE_BACKEND, "report_backend": REPORT_BACKEND, "openwebui_reach": OPENWEBUI_REACH, "console_transact": CONSOLE_TRANSACT, "net_config_change": NET_CFGCHG, "net_syslog_flow": NET_FLOW, "ups": UPS}},
}

SSH_OPTS = [
    "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
    "-o", "StrictHostKeyChecking=accept-new",
]


def run(ip, command):
    """Execute one check, locally if ip is None, else over SSH as monitor."""
    argv = ["bash", "-c", command] if ip is None else ["ssh", *SSH_OPTS, f"monitor@{ip}", command]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=CHECK_TIMEOUT)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, f"<timeout after {CHECK_TIMEOUT}s>"
    except Exception as exc:  # noqa: BLE001 - report, never crash the sweep
        return 1, f"<error: {exc}>"


# ---------------------------------------------------------------------------
# Metric parsers — best-effort; any failure degrades to {} rather than raising.
# ---------------------------------------------------------------------------
def parse_df(out):
    high, mx = {}, 0
    for line in out.splitlines():
        m = re.search(r"(\d+)%\s+(\S+)$", line)
        if m:
            pct, mount = int(m.group(1)), m.group(2)
            mx = max(mx, pct)
            if pct >= 80:
                high[mount] = pct
    return {"max_use_pct": mx, "high_mounts": high}


def parse_gpu(out):
    gpus = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 5:
            try:
                gpus.append({"name": parts[0], "temp_c": int(parts[1]),
                             "util_pct": int(parts[2]), "mem_used_mib": int(parts[3]),
                             "mem_total_mib": int(parts[4])})
            except ValueError:
                pass
    return {"gpus": gpus, "max_temp_c": max((g["temp_c"] for g in gpus), default=None)}


def parse_zpool(out):
    pools, healthy = {}, "all pools are healthy" in out.lower()
    tail = out.split("---", 1)[1] if "---" in out else out
    for line in tail.splitlines():
        parts = line.split()
        # NAME SIZE ALLOC FREE CKPOINT EXPANDSZ FRAG CAP DEDUP HEALTH ALTROOT
        if len(parts) >= 10 and parts[0] not in ("NAME",) and "%" in parts[7]:
            try:
                pools[parts[0]] = {"cap_pct": int(parts[7].rstrip("%")), "health": parts[9]}
            except (ValueError, IndexError):
                pass
    return {"status_healthy": healthy, "pools": pools}


def parse_smart(out):
    devices, failed = 0, []
    worst_pending = worst_realloc = 0
    max_temp = None
    dev = None
    for line in out.splitlines():
        if line.startswith("== /dev/"):
            dev = line.strip().strip("= ").strip()
            devices += 1
            continue
        low = line.lower()
        if "self-assessment test result: failed" in low or "smart health status: fail" in low or "failing_now" in low:
            if dev:
                failed.append(dev)
        m = re.search(r"reallocated_sector_ct\s+.*\s(\d+)$", low)
        if m:
            worst_realloc = max(worst_realloc, int(m.group(1)))
        m = re.search(r"current_pending_sector\s+.*\s(\d+)$", low)
        if m:
            worst_pending = max(worst_pending, int(m.group(1)))
        m = re.search(r"(?:temperature_celsius|airflow_temperature|current drive temperature)\D+(\d+)", low)
        if m:
            t = int(m.group(1))
            max_temp = t if max_temp is None else max(max_temp, t)
    return {"devices": devices, "failed": sorted(set(failed)),
            "worst_pending_sectors": worst_pending, "worst_reallocated": worst_realloc,
            "max_temp_c": max_temp}


# Kernel/journal lines that are cosmetic on this hardware — benign firmware,
# driver, and read-only-mount chatter that journalctl records at err priority
# but that needs no action. Filtered so they neither inflate error_lines nor
# reach the LLM interpreter (which had been narrating them as "kernel/service
# initialization errors"). Each pattern is kept tight so a genuinely new fault
# still surfaces. NB: NIC "Link is Down" is deliberately NOT filtered — that is
# real link state, not cosmetic.
BENIGN_JOURNAL_RE = re.compile(
    r"""(?ix)
    # --- kernel / firmware / driver chatter ---
      ACPI\ (Error|BIOS\ Error).*(IPMI|PMI0\._(GHL|PMC)|_OSC|AE_AML_BUFFER_LIMIT)  # Dell/SM ACPI-IPMI + _OSC buffer quirk
    | Region\ IPMI\ .*has\ no\ handler
    | SGX\ disabled\ or\ unsupported\ by\ BIOS
    | EXT4-fs\ .*write\ access\ unavailable,\ skipping\ orphan\ cleanup             # read-only snapshot mount during PBS backup
    | bnx2x\ .*Unqualified\ SFP\+\ module                                           # 10G DAC not on Broadcom whitelist
    | mpt2sas.*overriding\ NVDATA\ EEDPTagMode                                      # LSI/AVAGO HBA init info line
    | kernel:\s*$                                                                    # empty kernel message
    # --- always-present service / boot-ordering chatter (not real faults) ---
    | blkmapd.*open\ pipe\ file.*blocklayout\ failed                                # NFS pNFS block-layout pipe, cosmetic
    | pmxcfs.*\[(quorum|confdb|dcdb|status)\].*(_initialize\ failed:\ CS_ERR_LIBRARY|can't\ initialize\ service)  # boot race: pmxcfs starts before corosync, retries & connects
    | smartd.*no\ ATA\ CHECK\ POWER\ STATUS\ support                                # smartd -n directive notice, per-disk
    | proxmox-backup.*could\ not\ notify.*no\ recipients\ provided                  # PBS mail target unset (notification misconfig, not a health fault)
    | proxmox-backup-proxy.*HEAD\ /:\ 400\ Bad\ Request.*invalid\ http\ method      # external HEAD / probe
    | VM\ 100\ qga\ command.*guest-ping.*got\ timeout                               # OPNsense VM 100: agent=1 but FreeBSD appliance runs no qemu-ga; VM is healthy. Scoped to 100 so real agent timeouts (e.g. Wazuh VM 104) still surface.
    | pveproxy.*got\ inotify\ poll\ request\ in\ wrong\ process                     # benign PVE worker-fork message
    """,
)


def _split_journal(out):
    """Partition non-empty journal lines into (actionable, benign-filtered)."""
    actionable, benign = [], []
    for line in out.splitlines():
        if not line.strip():
            continue
        (benign if BENIGN_JOURNAL_RE.search(line) else actionable).append(line)
    return actionable, benign


def filter_benign_journal(out):
    """Raw journal text with known-cosmetic lines removed (for the LLM excerpt)."""
    return "\n".join(_split_journal(out)[0])


# ---------------------------------------------------------------------------
# journal_errors verdict. Until 2026-10-08 classify() returned "OK" for this check unconditionally,
# so the counts above were narrated by the interpreter but never moved a verdict. That hid pve4
# logging ~242 err lines per 20 minutes, all one message ("sshd-session[N]: error: no more
# sessions", 8,600 to 17,100 a day since 2026-09-11, caused by client ControlMaster fan-out).
#
# The verdict is now computed from the same parse as the metrics, so the two cannot disagree:
#   UNKNOWN  the window was not measured: journalctl exited non-zero, the output is empty or not
#            journalctl's short format, or the entries are not inside the 20-minute window
#            (stale or clock-skewed evidence). Never green.
#   CRIT     a storm: many actionable lines no named signature explains, or a very high total.
#   WARN     a named known signature repeating, any one normalized message repeating, or an
#            elevated count of actionable lines.
#   OK       measured, inside the window, below every threshold.
# Collection failures the generic path already names (TIMEOUT, AUTH-FAIL, UNREACHABLE) keep those
# verdicts: they are more specific than UNKNOWN and they fail the run's exit status.
#
# Thresholds are per 20-minute window, sized on 14 days of measured err journals (2026-09-24 to
# 2026-10-08, BENIGN_JOURNAL_RE applied) on jarvis, randy, quarkylab, pve2, pve3 and pve5. In 1,008
# windows per host the worst actionable count was 70 (jarvis), 42 (pve5), 21 (quarkylab), 19
# (pve2), 3 (randy) and 2 (pve3); the worst single repeated message was 28. Windows that would WARN:
# jarvis 5, pve5 1, quarkylab 1, all others 0 (each a real event: sshd/pam_systemd session failures,
# a corosync quorum loss, guest-agent timeouts). None would have reached CRIT.
JOURNAL_WINDOW_S = 20 * 60        # must match --since in JOURNAL
JOURNAL_WARN_LINES = 20           # actionable lines in the window
JOURNAL_REPEAT_WARN = 10          # one normalized message (or one known signature) this often
JOURNAL_STORM_LINES = 120         # actionable lines that no known signature explains (6/min)
JOURNAL_STORM_CEILING = 1200      # any actionable lines at all, known or not (60/min)
JOURNAL_CLOCK_SLACK_S = 300       # collection time plus modest clock skew

# Recurring messages with an identified cause. Naming one makes it WARN with its own reason when it
# repeats; it never makes it OK and it is never added to BENIGN_JOURNAL_RE. Names are exported as
# the `reason` label, so they must fit check_reason()'s [A-Z0-9_]{,32} contract.
KNOWN_JOURNAL_SIGNATURES = (
    # pve4 from 2026-09-11: MaxSessions exhausted by the wall dashboards' ControlMaster fan-out.
    ("SSHD_NO_MORE_SESSIONS",
     re.compile(r"\bsshd(?:-session)?(?:\[\d+\])?: error: no more sessions\b", re.I)),
)

_JOURNAL_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
# journalctl's default short format: "Oct 08 12:34:56 host ident[pid]: message".
_JOURNAL_ENTRY_RE = re.compile(r"^([A-Z][a-z]{2}) ([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) \S+ (.*)$")
# "-- No entries --" and the "-- Boot <id> --" separators are journalctl's own, not log entries.
_JOURNAL_MARKER_RE = re.compile(r"^-- .* --$")
# ssh's own notices on a first connection or a weak key exchange, merged in from stderr.
_SSH_NOTICE_RE = re.compile(r"^(?:Warning: Permanently added |\*\* )")


def normalize_journal_message(msg):
    """Collapse a journal message to its signature: PIDs, hex, IPs, ports and numbers removed, so
    "sshd-session[123]: error: no more sessions" and its 241 siblings count as one message."""
    msg = re.sub(r"\[\d+\]", "", msg)
    msg = re.sub(r"0x[0-9a-fA-F]+", "N", msg)
    msg = re.sub(r"\b[0-9a-fA-F]{8,}\b", "N", msg)
    msg = re.sub(r"\d+", "N", msg)
    return re.sub(r"\s+", " ", msg).strip()


def _journal_epoch(groups, now):
    """Local-time epoch of a short-format timestamp. The format has no year: take now's year, and the
    previous one when that would put the entry more than a day in the future (New Year)."""
    mon = _JOURNAL_MONTHS.get(groups[0])
    if mon is None:
        return None
    year = time.localtime(now).tm_year
    for y in (year, year - 1):
        try:
            t = time.mktime((y, mon, int(groups[1]), int(groups[2]), int(groups[3]),
                             int(groups[4]), 0, 0, -1))
        except (OverflowError, ValueError):
            return None
        if t <= now + 86400:
            return t
    return None


def parse_journal(out, rc=0, now=None):
    """Counts, signatures, and the verdict for one journal_errors run. Pure: `now` is injectable."""
    now = time.time() if now is None else now
    entries, benign, malformed, notices = [], 0, 0, 0
    oldest = newest = None
    for line in out.splitlines():
        if not line.strip():
            continue
        m = _JOURNAL_ENTRY_RE.match(line)
        if m:
            t = _journal_epoch(m.groups(), now)
            if t is None:
                malformed += 1
                continue
            oldest = t if oldest is None else min(oldest, t)
            newest = t if newest is None else max(newest, t)
            if BENIGN_JOURNAL_RE.search(line):
                benign += 1
            else:
                entries.append(m.group(6))
        elif _JOURNAL_MARKER_RE.match(line.strip()):
            continue
        elif line[:1].isspace() and (entries or benign):
            continue                      # continuation of a multi-line message
        elif _SSH_NOTICE_RE.match(line):
            notices += 1
        else:
            malformed += 1
    low = "\n".join(entries).lower()
    known = {}
    unexplained = []
    for msg in entries:
        for name, rx in KNOWN_JOURNAL_SIGNATURES:
            if rx.search(msg):
                known[name] = known.get(name, 0) + 1
                break
        else:
            unexplained.append(normalize_journal_message(msg))
    top_repeat = max((unexplained.count(s) for s in set(unexplained)), default=0)
    stale = (oldest is not None and oldest < now - JOURNAL_WINDOW_S - JOURNAL_CLOCK_SLACK_S) or \
            (newest is not None and newest > now + JOURNAL_CLOCK_SLACK_S)
    d = {"error_lines": len(entries), "benign_filtered": benign,
         "auth_failures": low.count("authentication failure") + low.count("failed password"),
         "service_failures": low.count("failed to start"),
         "unexplained_lines": len(unexplained), "top_repeat": top_repeat,
         "known_signatures": known, "malformed_lines": malformed, "ssh_notices": notices,
         "window_s": JOURNAL_WINDOW_S, "measured": True, "stale": bool(stale)}
    if rc != 0 or not out.strip() or malformed:
        # Not a measurement. Counts are withheld so no consumer can sum them as "0 errors".
        for k in ("error_lines", "benign_filtered", "auth_failures", "service_failures",
                  "unexplained_lines", "top_repeat"):
            d[k] = None
        d["known_signatures"], d["measured"], d["stale"] = {}, False, None
        # Empty output with rc 0 is malformed too: journalctl always prints "-- No entries --".
        d["state"], d["reason"] = "UNKNOWN", ("UNMEASURED" if rc != 0 else "MALFORMED")
        return d
    top_known = max(known.items(), key=lambda kv: kv[1], default=(None, 0))
    if stale:
        d["state"], d["reason"] = "UNKNOWN", REASON_STALE
    elif len(entries) >= JOURNAL_STORM_CEILING or len(unexplained) >= JOURNAL_STORM_LINES:
        d["state"], d["reason"] = "CRIT", "STORM"
    elif top_known[1] >= JOURNAL_REPEAT_WARN:
        d["state"], d["reason"] = "WARN", top_known[0]
    elif top_repeat >= JOURNAL_REPEAT_WARN:
        d["state"], d["reason"] = "WARN", "REPEATED"
    elif len(entries) >= JOURNAL_WARN_LINES:
        d["state"], d["reason"] = "WARN", "ELEVATED"
    else:
        d["state"], d["reason"] = "OK", ""
    return d


def parse_pbs(out):
    return {"lines": len([line for line in out.splitlines() if line.strip()])}


def _backup_verify_load(out):
    """Parse the backup-verify report JSON; None if absent/unreadable/not JSON."""
    if not out or not out.strip():
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def _backup_verify_age_h(data):
    """Report age in hours from its own generated_epoch; None if unusable."""
    gen = data.get("generated_epoch")
    if not isinstance(gen, (int, float)):
        return None
    return round((datetime.now(timezone.utc).timestamp() - gen) / 3600, 1)


def parse_hardening_drift(out):
    """Parse the hardening drift report (same JSON-cat pattern as backup_verify). Reports
    whether any node drifted from the hardened baseline, and the report's own age."""
    data = _backup_verify_load(out)  # generic JSON loader (None if absent/unreadable)
    if data is None:
        return {"present": False}
    age_h = _backup_verify_age_h(data)  # reuses generated_epoch age logic
    drifted = data.get("drifted_nodes", "").strip()
    return {"present": True,
            "any_drift": bool(data.get("any_drift")),
            "drifted_nodes": [n for n in drifted.split() if n],
            "node_count": len(data.get("nodes", {})),
            "generated": data.get("generated"),
            "age_hours": age_h,
            "stale": age_h is None or age_h > HARDENING_DRIFT_MAX_AGE_H}


def parse_restore_verify(out):
    """Parse the monthly restore-verify evidence (same JSON-cat pattern as backup_verify).

    Keeps THREE facts apart, because collapsing them is how a recovery claim becomes untrue:
      what the drill PROVED      status + level + failure_class
      whether it was DELIVERED   present
      whether it is RECENT       age_hours + stale

    `claim` states the recovery level literally. LEVEL 2 means one file was extracted from an
    identified snapshot into a scratch directory. It is NOT a boot test and NOT an application
    recovery test, and this parser deliberately has no wording that could be read as either.
    """
    data = _backup_verify_load(out)
    if data is None:
        return {"present": False}
    age_h = _backup_verify_age_h(data)
    level = data.get("level")
    # A timestamp in the future is not fresh evidence, it is a broken clock somewhere. Allow an
    # hour of skew, then refuse to treat it as recent; otherwise a wrong clock reads as OK forever.
    clock_anomaly = age_h is not None and age_h < -1
    return {"present": True,
            "status": data.get("status"),
            "level": level,
            "level_name": data.get("level_name"),
            "claim": "NOTHING_PROVEN" if level is None
                     else f"LEVEL {level} {data.get('level_name')}",
            "snapshot": data.get("snapshot") or None,
            "failure_class": data.get("failure_class") or None,
            "stale_lock_recovered": bool(data.get("stale_lock_recovered")),
            "generated": data.get("generated"),
            "age_hours": age_h,
            "clock_anomaly": clock_anomaly,
            "stale": age_h is None or age_h > RESTORE_VERIFY_MAX_AGE_H or clock_anomaly,
            "source": "randy:/var/log/netframe-monitor/restore-verify.json"}


def parse_backup_verify(out):
    data = _backup_verify_load(out)
    if data is None:
        return {"present": False}
    checks = {c.get("name"): c.get("status") for c in data.get("checks", [])}
    age_h = _backup_verify_age_h(data)
    return {"present": True,
            "overall": data.get("overall"),
            "checks": checks,
            "failed": sorted(n for n, s in checks.items() if s != "pass"),
            "generated": data.get("generated"),
            "age_hours": age_h,
            "stale": age_h is None or age_h > BACKUP_VERIFY_MAX_AGE_H}


def _guest_rows(out):
    """Normalize `pct list` / `qm list` output to (vmid, name, status) rows.

    pct list:  VMID Status [Lock] Name
    qm list:   VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID
    """
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        if parts[1].lower() in ("running", "stopped", "paused", "suspended"):
            status, name = parts[1].lower(), parts[-1]  # pct: status is col 2
        else:
            status, name = parts[2].lower(), parts[1]    # qm: name col 2, status col 3
        rows.append((parts[0], name, status))
    return rows


def parse_guests(out):
    rows = _guest_rows(out)
    guests = {name: status for _, name, status in rows}
    running = sum(1 for _, _, s in rows if s == "running")
    down_monitoring = sorted(n for n, s in guests.items()
                             if s != "running" and n.lower() in MONITORING_GUESTS)
    return {"total": len(rows), "running": running, "stopped": len(rows) - running,
            "guests": guests, "down_monitoring": down_monitoring}


_GUEST_CACHE = {}


def guest_inventory():
    """The tracked guest inventory, or None when it cannot be read (guest_state then reads UNKNOWN)."""
    if "inventory" not in _GUEST_CACHE:
        try:
            _GUEST_CACHE["inventory"] = GS.load_inventory(GUEST_INVENTORY)
        except (OSError, ValueError, KeyError):
            _GUEST_CACHE["inventory"] = None
    return _GUEST_CACHE["inventory"]


def parse_guest_state(out, rc=0, now=None, host=None):
    """guest_state metrics (with verdict and reason) for one wrapper run on `host`. Pure apart from
    the cached inventory read; `now` is injectable. Without `host` the node cannot be confirmed, so
    the collection reads COLLECTION_FAILED (WRONG_NODE), never OK."""
    now = time.time() if now is None else now
    return GS.evaluate(out, rc=rc, host=host, now=now, inventory=guest_inventory())


def parse_grafana(out):
    db = re.search(r'"database"\s*:\s*"([^"]+)"', out)
    ver = re.search(r'"version"\s*:\s*"([^"]+)"', out)
    return {"database": db.group(1) if db else None,
            "version": ver.group(1) if ver else None,
            "up": bool(db) and db.group(1) == "ok"}


def parse_prometheus(out):
    return {"up": "healthy" in out.lower()}


def parse_loki(out):
    ver = re.search(r'"version"\s*:\s*"([^"]+)"', out)
    return {"up": bool(ver), "version": ver.group(1) if ver else None}


def parse_netlog(out):
    """Loki instant-query scalar: {"data":{"result":[{"value":[ts,"N"]}]}} -> count."""
    try:
        r = json.loads(out)["data"]["result"]
        return {"count": float(r[0]["value"][1]) if r else 0.0}
    except (ValueError, KeyError, IndexError, TypeError):
        return {"count": None}


def parse_pihole(out):
    dns_ip, http_code, section = None, None, None
    for line in out.splitlines():
        s = line.strip()
        if s == "DNS:":
            section = "dns"
            continue
        if s == "HTTP:":
            section = "http"
            continue
        if section == "dns" and re.match(r"\d+\.\d+\.\d+\.\d+$", s):
            dns_ip = dns_ip or s
        elif section == "http":
            m = re.search(r"\d{3}", s)
            if m:
                http_code = int(m.group(0))
    return {"dns_up": dns_ip is not None, "dns_answer": dns_ip,
            "http_code": http_code, "up": dns_ip is not None}


def parse_page_auth(out):
    m = re.search(r"HTTP\s+(\d{3})", out)
    code = int(m.group(1)) if m else None
    return {"http_code": code, "auth_enforced": code == 401}


def parse_llm_router(out):
    m = re.search(r"HTTP\s+(\d{3})", out)
    code = int(m.group(1)) if m else None
    return {"http_code": code, "up": code == 200}


def parse_npm_dns(out):
    """Parse the NPM DNS audit: per-host OK/MISSING lines + a 'total=N missing=M' summary.
    Keeps the list of missing hostnames so a finding names the exact gap."""
    m = re.search(r"total=(\d+)\s+missing=(\d+)", out)
    total = int(m.group(1)) if m else 0
    missing_ct = int(m.group(2)) if m else 0
    missing = [ln.split("=")[0] for ln in out.splitlines() if ln.strip().endswith("=MISSING")]
    enumerate_ok = "enumerate=FAIL" not in out
    return {"total": total, "missing_count": missing_ct, "missing": missing,
            "enumerate_ok": enumerate_ok}


def parse_llm_router_conformance(out):
    """Parse the conformance wrapper's key=value lines into a dict. Keeps the three
    dimensions (config/runtime/firewall) as SEPARATE fields - never collapsed - so the
    interpreter can say which one failed and therefore what to do about it."""
    m = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            m[k.strip()] = v.strip()
    return m


def parse_wan_posture(out):
    """Parse the dual-WAN posture wrapper's key=value lines into typed, semantic fields.

    Every field is UNKNOWN (None) unless the wrapper actually stated it. That asymmetry is the
    whole point: this feeds a wall display whose green state means "a WAN1 failure is survivable",
    and a missing field must never be read as a healthy one. The 2026-08/09 regression it guards
    against was exactly this - one absent fact rendered as green for 25 days while the FirstNet
    standby was dead.

    `armed` is tri-state on purpose: True, False and None are three different operational
    situations (protected / knowingly unprotected / not observed) and collapsing None into False
    would turn "the collector could not look" into a false alarm."""
    kv = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()

    def tri(key):
        v = kv.get(key)
        return True if v == "true" else False if v == "false" else None

    source_ok = tri("source_ok")
    armed = tri("armed") if source_ok else None          # a failed read states nothing about arming
    path = kv.get("active_path") if source_ok else None
    if path not in ("wan1", "wan2"):
        path = None                                       # "unknown" and anything unexpected -> UNKNOWN
    tiers = kv.get("tiers")
    return {
        "source_ok": source_ok,
        "armed": armed,
        "group": kv.get("group") if armed else None,
        "tiers": int(tiers) if (tiers or "").isdigit() else None,
        "active_path": path,
        "active_netif": kv.get("active_netif") if source_ok else None,
        "reason": kv.get("reason") if source_ok is False else None,
    }


def parse_transact(out):
    """Parse netframe_transact.py's key=value line. `reason` may contain spaces, so it is
    taken as the remainder of the line."""
    m = re.search(r"reason=(.*)$", out.strip(), re.MULTILINE)
    reason = m.group(1).strip() if m else None
    kv = dict(re.findall(r"(\w+)=(\S+)", out))
    attempted = kv.get("attempted") == "YES"
    return {"attempted": attempted,
            "reason": None if attempted else reason,
            "result": kv.get("result"),
            "http_code": int(kv["http"]) if kv.get("http", "").isdigit() else None,
            "model": kv.get("model"),
            "elapsed_s": int(kv["elapsed_s"]) if kv.get("elapsed_s", "").isdigit() else None,
            # Tri-state, deliberately not a bool: True = verified working, False = verified
            # broken, None = NOT TESTED. Collapsing None into False would turn "we did not
            # look" into "it is broken", which is the failure this whole phase exists to end.
            "functionally_verified": (kv.get("result") == "PASS") if attempted else None}


_WAZUH_CACHE = {}


def wazuh_expected():
    """The tracked expected-agents list, or None when it cannot be read (A and T then read UNKNOWN)."""
    if "expected" not in _WAZUH_CACHE:
        try:
            _WAZUH_CACHE["expected"] = WH.load_expected(WAZUH_EXPECTED_AGENTS)
        except (OSError, ValueError, KeyError):
            _WAZUH_CACHE["expected"] = None
    return _WAZUH_CACHE["expected"]


def wazuh_prev():
    """The previous run's Wazuh drop sample from history.jsonl, or None. Drops are judged on the
    change since that run, because the daemons' counters are cumulative."""
    if "prev" not in _WAZUH_CACHE:
        prev = None
        try:
            with open(HISTORY_FILE) as fh:
                lines = fh.readlines()
            for line in reversed(lines[-5:]):
                rec = json.loads(line)
                prev = WH.prev_from_flat(rec.get("metrics"), "wazuh.wazuh")
                if prev:
                    break
        except (OSError, ValueError):
            prev = None
        _WAZUH_CACHE["prev"] = prev
    return _WAZUH_CACHE["prev"]


def parse_wazuh(out):
    """The full Packet C health result (seven inputs, both trees) for the `wazuh` check."""
    return WH.evaluate(WH.parse_kv(out), wazuh_expected(), prev=wazuh_prev())


def wazuh_coverage(wazuh_check):
    """The integrity tree (agents, auth telemetry, drops) as its own check, derived from the SAME
    wrapper run as `wazuh`. A run that never produced a health result reads UNKNOWN, never OK."""
    m = (wazuh_check or {}).get("metrics") or {}
    if "inputs" not in m:
        res = WH.unmeasured()
    else:
        res = m
    return {"verdict": WH.verdict(res["integrity"]), "rc": (wazuh_check or {}).get("rc"),
            "metrics": {"tree": "integrity", "state": res["integrity"],
                        "summary": res["integrity_summary"],
                        "inputs": {k: res["inputs"][k] for k in WH.INTEGRITY}},
            "raw_excerpt": ""}


def parse_ups(out):
    """Per-UPS status/charge from upsc output blocks (== name == headers)."""
    ups = {}
    cur = None
    for line in out.splitlines():
        m = re.match(r"==\s*(\S+)\s*==", line)
        if m:
            cur = m.group(1)
            ups[cur] = {}
            continue
        m = re.match(r"\s*(ups\.status|battery\.charge|battery\.runtime):\s*(.+)", line)
        if m and cur:
            ups[cur][m.group(1)] = m.group(2).strip()
    charges = [int(float(v["battery.charge"])) for v in ups.values()
               if v.get("battery.charge", "").replace(".", "").isdigit()]
    statuses = [v.get("ups.status", "") for v in ups.values()]
    return {"ups": ups, "reporting": sum(1 for v in ups.values() if v),
            "min_charge": min(charges) if charges else None,
            "all_online": bool(statuses) and all(
                "OL" in s and "OB" not in s and "LB" not in s for s in statuses)}


PARSERS = {"df": parse_df, "gpu": parse_gpu, "zpool": parse_zpool,
           "smart": parse_smart, "journal_errors": parse_journal, "pbs": parse_pbs,
           "backup_verify": parse_backup_verify,
           "hardening_drift": parse_hardening_drift,
           "restore_verify": parse_restore_verify,
           "guests": parse_guests, "grafana": parse_grafana,
           "prometheus": parse_prometheus, "loki": parse_loki, "pihole": parse_pihole,
           "wazuh": parse_wazuh, "page_auth": parse_page_auth,
           "console_auth": parse_page_auth, "llm_router": parse_llm_router,
           "console_backend": parse_llm_router, "report_backend": parse_llm_router,
           "openwebui_reach": parse_llm_router, "console_transact": parse_transact,
           "llm_router_conformance": parse_llm_router_conformance,
           "npm_dns": parse_npm_dns, "wan_failover": parse_wan_posture,
           "net_config_change": parse_netlog, "net_syslog_flow": parse_netlog,
           "ups": parse_ups}


def classify(name, rc, out, now=None, host=None):
    """Coarse health verdict; auth detection keys off the command's OWN output
    (sudo's "sudo:" stderr / ssh publickey errors), never on substrings that can
    appear inside journal/SMART log text. `now` is used only by journal_errors' window check and
    guest_state's freshness check; `host` only by guest_state, to confirm which node answered."""
    low = out.lower()
    if rc == 124:
        return "TIMEOUT"
    for line in out.splitlines():
        s = line.strip().lower()
        if s.startswith("sudo:") and ("password is required" in s or "a terminal is required" in s or "not allowed" in s):
            return "AUTH-FAIL"
    if "permission denied (publickey" in low or "host key verification failed" in low:
        return "AUTH-FAIL"
    # Node down must say so, not fall through to per-check defaults (the 2026-07-16
    # pve3 outage read as journal_errors=OK / smart=OK). Keyed off ssh's OWN
    # connect-error line (starts "ssh:"), never journal/log text, same anti-spoof
    # rule as AUTH-FAIL; journalctl lines start with timestamps so cannot match.
    if rc == 255:
        for line in out.splitlines():
            s = line.strip().lower()
            if s.startswith("ssh:") and ("no route to host" in s
                                          or "connection timed out" in s
                                          or "connection refused" in s
                                          or "network is unreachable" in s
                                          or "could not resolve hostname" in s):
                return "UNREACHABLE"
    if name == "guests":
        if rc != 0:
            return "WARN"
        for _, gname, status in _guest_rows(out):
            if gname.lower() in MONITORING_GUESTS and status != "running":
                return "WARN"  # a monitoring guest is down
        return "OK"
    if name == "guest_state":
        return parse_guest_state(out, rc=rc, now=now, host=host)["verdict"]
    if name == "grafana":
        if rc != 0:
            return "WARN"  # endpoint unreachable / HTTP error
        return "OK" if re.search(r'"database"\s*:\s*"ok"', out) else "WARN"
    if name == "ups":
        # WARN when a UPS is on battery / low battery, or when fewer than BOTH
        # UPSes report (NUT unreachable = UPS monitoring itself is lost — the
        # AAR gap: it used to die silently with pve3).
        d = parse_ups(out)
        if d["reporting"] < 2:
            return "WARN"
        return "OK" if d["all_online"] else "WARN"
    if name == "prometheus":
        return "OK" if "healthy" in low else "WARN"
    if name == "loki":
        return "OK" if rc == 0 and '"version"' in out else "WARN"
    if name == "net_config_change":
        # Informational: config-change count rides in metrics for the interpreter to
        # reason about ("did the firewall/switch change?"). Never alarms the verdict.
        return "OK"
    if name == "net_syslog_flow":
        # Dead-man: WARN if the network-syslog stream dried up (logging stopped).
        if rc != 0:
            return "WARN"
        c = parse_netlog(out)["count"]
        return "WARN" if (c is None or c < 10) else "OK"
    if name == "pihole":
        # OK when Pi-hole answers DNS (its core function).
        for line in out.splitlines():
            if re.match(r"\s*\d+\.\d+\.\d+\.\d+$", line.strip()):
                return "OK"
        return "WARN"
    if name in ("page_auth", "console_auth"):
        # 401 = NPM auth enforced (healthy). 200 = access list detached (public!).
        m = re.search(r"HTTP\s+(\d{3})", out)
        return "OK" if (m and m.group(1) == "401") else "WARN"
    if name in ("llm_router", "console_backend", "report_backend", "openwebui_reach"):
        # 200 = the thing actually serves. For llm_router, 502 = NPM reached but the
        # backend didn't answer (the loopback-bind case); 000 = DNS or NPM itself down.
        m = re.search(r"HTTP\s+(\d{3})", out)
        return "OK" if (m and m.group(1) == "200") else "WARN"
    if name == "npm_dns":
        # WARN if any published NPM host does not resolve on Pi-hole (a missing local
        # record). If enumeration failed or 0 hosts came back, that is inconclusive (LXC
        # 101 / NPM issue), also WARN so it is not silently green. All-resolve = OK.
        d = parse_npm_dns(out)
        if not d["enumerate_ok"] or d["total"] == 0:
            return "WARN"
        return "OK" if d["missing_count"] == 0 else "WARN"
    if name == "wan_failover":
        # The estate is protected only when a standby path is armed AND traffic is on the primary.
        # Every other situation is operationally different, and none of them is OK:
        #   source unreadable -> we cannot see the safety net, which is not the same as having one
        #   armed is not True -> a WAN1 failure would be an internet outage, not a failover
        #   active is wan2    -> already running ON the LTE standby, with nothing left to fall back to
        #   active is unknown -> pf did not state the path, so "on the primary" is unproven
        d = parse_wan_posture(out)
        if d["source_ok"] is not True or d["armed"] is not True:
            return "WARN"
        return "OK" if d["active_path"] == "wan1" else "WARN"
    if name == "llm_router_conformance":
        # OK only when ALL three dimensions pass. But the per-dimension verdicts in the
        # metrics are what the interpreter reads to say WHICH failed (config -> edit the
        # file; runtime -> restart the unit; firewall -> reassert the lock). A single
        # collapsed boolean would lose exactly the information that makes this useful.
        m = parse_llm_router_conformance(out)
        dims = [m.get("config"), m.get("runtime"), m.get("firewall")]
        if any(d == "FAIL" for d in dims):
            return "WARN"
        if any(d in (None, "UNKNOWN") for d in dims):
            return "WARN"  # cannot confirm conformance != conformant
        return "OK"
    if name.endswith("_transact"):
        # SKIPPED is neither health nor failure: it says the functional test could not be
        # run under acceptable conditions. Reporting it as WARN would cry wolf every time
        # someone actually used the GPU; reporting it as OK would claim a verification we
        # never performed. It gets its own verdict and does not move the overall one.
        data = parse_transact(out)
        if not data["attempted"]:
            return "SKIPPED"
        return "OK" if data["result"] == "PASS" else "WARN"
    if name == "wazuh":
        # The SERVICES tree: worst(manager, indexer, dashboard, Filebeat). The integrity tree is the
        # derived `wazuh_coverage` check. A report that does not parse is UNKNOWN, never OK.
        return WH.verdict(parse_wazuh(out)["services"])
    if name == "backup_verify":
        data = _backup_verify_load(out)
        if data is None:
            return "WARN"  # report missing / unreadable / not JSON
        age_h = _backup_verify_age_h(data)
        if age_h is None or age_h > BACKUP_VERIFY_MAX_AGE_H:
            return "WARN"  # stale report => dead cron/timer on Ares
        return "OK" if data.get("overall") == "pass" else "WARN"
    if name == "restore_verify":
        d = parse_restore_verify(out)
        # Every non-OK case is WARN, matching backup_verify: the monitor's vocabulary is coarse on
        # purpose. WHICH problem it is lives in the parsed metrics, so REPOSITORY_LOCKED is never
        # rendered as corruption. That conflation was the defect repaired on 2026-09-02.
        if not d.get("present"):
            return "WARN"        # report missing, unreadable, or not JSON
        if d.get("stale"):
            return "WARN"        # the monthly drill did not run, or the clock is wrong
        if d.get("status") != "pass":
            return "WARN"        # it ran and did not prove a restore
        if (d.get("level") or 0) < 2:
            return "WARN"        # passed, but did not reach RESTORE_EXTRACTED
        return "OK"
    if name == "hardening_drift":
        d = parse_hardening_drift(out)
        if not d.get("present"):
            return "WARN"        # report missing / unreadable
        if d.get("stale"):
            return "WARN"        # stale => the daily drift-check cron stopped
        return "WARN" if d.get("any_drift") else "OK"
    if name == "smart":
        if "self-assessment test result: failed" in low or "failing_now" in low or "smart health status: fail" in low:
            return "WARN"
        return "OK"
    if name == "zpool":
        return "OK" if "all pools are healthy" in low else "WARN"
    if name == "journal_errors":
        return parse_journal(out, rc=rc, now=now)["state"]
    return "OK" if rc == 0 else "WARN"


def check_reason(name, metrics):
    """A bounded, low-cardinality reason for a non-OK report check, or "" when there is none.

    Deliberately NOT the failure detail. `detail` carries captured stderr and belongs in the report,
    not in a metric label. What survives here is the CLASS, which comes from a fixed vocabulary the
    producers already define, sanitized so that a producer bug cannot turn a label into free text.
    """
    if not isinstance(metrics, dict):
        return ""
    if metrics.get("present") is False:
        return REASON_ABSENT
    if metrics.get("stale"):
        return REASON_STALE
    raw = ""
    if name == "wazuh" and "inputs" in metrics:
        raw = WH.primary_reason(metrics, WH.SERVICES)
    elif name == "wazuh_coverage" and "inputs" in metrics:
        raw = WH.primary_reason({"inputs": {**{k: {"state": "NOMINAL", "reasons": []}
                                                  for k in WH.SERVICES}, **metrics["inputs"]}},
                                WH.INTEGRITY)
    elif name == "restore_verify":
        raw = metrics.get("failure_class") or ""
    elif name == "hardening_drift":
        raw = "DRIFT" if metrics.get("any_drift") else ""
    elif name == "backup_verify":
        raw = "FAILED_CHECKS" if metrics.get("failed") else ""
    elif name in ("journal_errors", "guest_state"):
        raw = metrics.get("reason") or ""
    clean = re.sub(r"[^A-Za-z0-9_]", "", str(raw)).upper()[:_REASON_MAX]
    return clean


def render_metrics(report, now=None):
    """The textfile document. Pure function so it can be tested without a filesystem."""
    ts = int(now if now is not None else time.time())
    lines = [
        "# HELP netframe_monitor_check_status Current netframe_monitor verdict per node and check.",
        "# TYPE netframe_monitor_check_status gauge",
    ]
    seen = set()
    for host, checks in sorted(report.get("nodes", {}).items()):
        for name, c in sorted(checks.items()):
            state = str(c.get("verdict", "UNKNOWN")).lower()
            reason = check_reason(name, c.get("metrics"))
            key = (host, name)
            if key in seen:      # one series per node/check, never a duplicate
                continue
            seen.add(key)
            lines.append(
                f'netframe_monitor_check_status{{node="{host}",check="{name}",'
                f'state="{state}",reason="{reason}"}} 1')
    wz = ((report.get("nodes", {}).get("wazuh") or {}).get("wazuh") or {}).get("metrics") or {}
    if "inputs" in wz:
        lines += WH.prom_lines(wz, wazuh_expected() or [])
    lines += [
        "# HELP netframe_monitor_export_timestamp_seconds Unix time this export was written.",
        "# TYPE netframe_monitor_export_timestamp_seconds gauge",
        f"netframe_monitor_export_timestamp_seconds {ts}",
        "",
    ]
    return "\n".join(lines)


def export_metrics(report, directory=TEXTFILE_DIR, name=TEXTFILE_NAME, now=None):
    """Write the metrics atomically. Returns True on success.

    ATOMICITY: written to a temporary file in the SAME directory and renamed over the target, so
    node_exporter never reads a half-written document. A partial .prom is not merely noisy - it
    makes the collector drop the whole file, so every series would vanish at once.

    ON FAILURE the previous file is left in place rather than removed. Deleting it would destroy the
    last known observation, and absence is not a safer signal than an old one: the export timestamp
    inside the old file keeps ageing, so the monitor-export-stale rule takes over and the stale
    values stop being trusted. Evidence is preserved AND it expires.
    """
    if not os.path.isdir(directory):
        return False
    target = os.path.join(directory, name)
    tmp = os.path.join(directory, f".{name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w") as fh:
            fh.write(render_metrics(report, now=now))
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
        return True
    except OSError as exc:
        print(f"WARN: could not write {target}: {exc}", file=sys.stderr)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


def flatten_metrics(nodes):
    """Compact numeric view for history.jsonl trend tracking."""
    flat = {}
    for host, checks in nodes.items():
        for name, c in checks.items():
            m = c.get("metrics", {})
            if name == "df" and m.get("max_use_pct") is not None:
                flat[f"{host}.df.max_use_pct"] = m["max_use_pct"]
            if name == "gpu" and m.get("max_temp_c") is not None:
                flat[f"{host}.gpu.max_temp_c"] = m["max_temp_c"]
            if name == "zpool":
                for pool, pm in m.get("pools", {}).items():
                    flat[f"{host}.zpool.{pool}.cap_pct"] = pm.get("cap_pct")
            if name == "smart":
                flat[f"{host}.smart.worst_pending"] = m.get("worst_pending_sectors", 0)
                flat[f"{host}.smart.worst_realloc"] = m.get("worst_reallocated", 0)
                if m.get("max_temp_c") is not None:
                    flat[f"{host}.smart.max_temp_c"] = m["max_temp_c"]
            if name == "guests":
                flat[f"{host}.guests.running"] = m.get("running")
                flat[f"{host}.guests.stopped"] = m.get("stopped")
            if name == "guest_state":
                flat.update(GS.flat(m, f"{host}.guest_state"))
            if name == "ups":
                flat[f"{host}.ups.reporting"] = m.get("reporting")
                if m.get("min_charge") is not None:
                    flat[f"{host}.ups.min_charge"] = m["min_charge"]
            if name in ("grafana", "prometheus", "loki", "pihole", "llm_router",
                        "console_backend", "report_backend", "openwebui_reach"):
                flat[f"{host}.{name}.up"] = 1 if m.get("up") else 0
            if name == "llm_router_conformance":
                # Keep the three dimensions as separate trend series (1=PASS, 0=not),
                # so history/predict can show WHICH dimension flapped, not just that
                # something did.
                for dim in ("config", "runtime", "firewall"):
                    v = m.get(dim)
                    if v in ("PASS", "FAIL"):
                        flat[f"{host}.llm_router_conformance.{dim}"] = 1 if v == "PASS" else 0
            if name == "wan_failover":
                # Tri-state fields flattened as SEPARATE series, and only when actually
                # observed. Writing 0 for "not observed" would make a collector that could
                # not reach pve2 indistinguishable in the history from a genuinely unarmed
                # failover, and every trend built on it would then be wrong.
                if m.get("armed") is not None:
                    flat[f"{host}.wan_failover.armed"] = 1 if m["armed"] else 0
                if m.get("active_path") is not None:
                    flat[f"{host}.wan_failover.on_primary"] = 1 if m["active_path"] == "wan1" else 0
            if name.endswith("_transact"):
                # Only record the trend when the probe actually ran. Writing 0 for a skip
                # would make "we didn't test" indistinguishable from "it failed" in the
                # history, and every trend built on it would be wrong.
                if m.get("functionally_verified") is not None:
                    flat[f"{host}.{name}.verified"] = 1 if m["functionally_verified"] else 0
            if name == "wazuh":
                flat[f"{host}.wazuh.up"] = 1 if m.get("up") else 0
                if "inputs" in m:
                    flat.update(WH.flat(m, f"{host}.wazuh"))
            if name in ("page_auth", "console_auth"):
                flat[f"{host}.{name}.enforced"] = 1 if m.get("auth_enforced") else 0
            if name == "backup_verify":
                ok = m.get("present") and m.get("overall") == "pass" and not m.get("stale")
                flat[f"{host}.backup_verify.ok"] = 1 if ok else 0
                if m.get("age_hours") is not None:
                    flat[f"{host}.backup_verify.age_hours"] = m["age_hours"]
            if name == "restore_verify":
                ok = (m.get("present") and m.get("status") == "pass"
                      and (m.get("level") or 0) >= 2 and not m.get("stale"))
                flat[f"{host}.restore_verify.ok"] = 1 if ok else 0
                if m.get("level") is not None:
                    flat[f"{host}.restore_verify.level"] = m["level"]
                if m.get("age_hours") is not None:
                    flat[f"{host}.restore_verify.age_hours"] = m["age_hours"]
    return flat


def append_history(record):
    try:
        lines = []
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE) as fh:
                lines = fh.readlines()
        lines.append(json.dumps(record) + "\n")
        with open(HISTORY_FILE, "w") as fh:
            fh.writelines(lines[-HISTORY_CAP:])
    except OSError as exc:
        print(f"WARN: could not write {HISTORY_FILE}: {exc}", file=sys.stderr)


#: Verdicts that mean the check could not be COLLECTED. They, and only they, fail the run's exit
#: status, so `systemctl status` keeps surfacing a broken collection path. CRIT shares their rank since
#: Packet C, so the exit status can no longer be read off `worst`: a measured CRIT seen first would
#: otherwise hide every later AUTH-FAIL.
COLLECTION_FAILURES = ("AUTH-FAIL", "TIMEOUT", "UNREACHABLE")


def _worse(verdict, than):
    """True when `verdict` should replace `than` as the run's worst. On a tie in rank a collection
    failure wins over a measured verdict, so the report's headline never hides a blind check."""
    a = VERDICT_RANK.get(verdict, VERDICT_RANK_DEFAULT)
    b = VERDICT_RANK.get(than, VERDICT_RANK_DEFAULT)
    return a > b or (a == b and verdict in COLLECTION_FAILURES and than not in COLLECTION_FAILURES)


def main():
    started = datetime.now(timezone.utc)
    report = {"started": started.isoformat(), "runner": socket.gethostname(), "nodes": {}}
    worst = "OK"
    collection_failed = False

    print(f"=== NetFRAME cluster health monitor — {started.isoformat()} ===")
    for host, cfg in NODES.items():
        ip = cfg["ip"]
        label = f"{host} (local)" if ip is None else f"{host} ({ip})"
        print(f"\n########## {label} ##########")
        node_result = {}
        for name, command in cfg["checks"].items():
            rc, out = run(ip, command)
            now = time.time()
            verdict = classify(name, rc, out, now=now, host=host)
            collection_failed = collection_failed or verdict in COLLECTION_FAILURES
            if _worse(verdict, worst):
                worst = verdict
            try:
                if name == "journal_errors":
                    metrics = parse_journal(out, rc=rc, now=now)  # same inputs as the verdict
                elif name == "guest_state":
                    metrics = parse_guest_state(out, rc=rc, now=now, host=host)
                else:
                    metrics = PARSERS[name](out) if name in PARSERS else {}
            except Exception as exc:  # noqa: BLE001
                metrics = {"parse_error": str(exc)}
            # Strip cosmetic kernel chatter from the journal excerpt the
            # interpreter reads, so genuine errors aren't buried in noise.
            excerpt = filter_benign_journal(out) if name == "journal_errors" else out
            node_result[name] = {"verdict": verdict, "rc": rc, "metrics": metrics,
                                 "raw_excerpt": excerpt[:RAW_EXCERPT]}
            print(f"\n--- [{verdict}] {host}:{name} (rc={rc}) ---")
            print(out if out else "<no output>")
        if "wazuh" in node_result:
            cov = wazuh_coverage(node_result["wazuh"])
            node_result["wazuh_coverage"] = cov
            if _worse(cov["verdict"], worst):
                worst = cov["verdict"]
            print(f"\n--- [{cov['verdict']}] {host}:wazuh_coverage (derived) ---")
            print(cov["metrics"]["summary"])
        report["nodes"][host] = node_result

    report["worst"] = worst
    report["finished"] = datetime.now(timezone.utc).isoformat()

    print("\n=== SUMMARY ===")
    for host, checks in report["nodes"].items():
        flat = " ".join(f"{n}:{c['verdict']}" for n, c in checks.items())
        print(f"  {host:<10} {flat}")
    print(f"\nOverall: {worst}")

    try:
        with open(STATE_FILE, "w") as fh:
            json.dump(report, fh, indent=2)
    except OSError as exc:
        print(f"WARN: could not write {STATE_FILE}: {exc}", file=sys.stderr)

    export_metrics(report)

    verdicts = {f"{h}.{n}": c["verdict"]
                for h, checks in report["nodes"].items() for n, c in checks.items()}
    append_history({"ts": started.isoformat(), "worst": worst,
                    "verdicts": verdicts, "metrics": flatten_metrics(report["nodes"])})

    return 1 if collection_failed else 0


if __name__ == "__main__":
    sys.exit(main())
