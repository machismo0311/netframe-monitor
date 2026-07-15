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
from datetime import datetime, timezone

BASE = "/opt/netframe-monitor"
KEY = f"{BASE}/monitor_key"
STATE_FILE = f"{BASE}/last_run.json"
HISTORY_FILE = f"{BASE}/history.jsonl"
HISTORY_CAP = 3400  # ~35 days at the 15-min cadence, so the 14d predict and 30d
                    # monthly windows are actually populated; a few MB at most

CHECK_TIMEOUT = 120  # Randy's SMART sweep over 50+ SAS disks is the slow path
RAW_EXCERPT = 1200   # chars of raw output kept per check in last_run.json

# ---------------------------------------------------------------------------
# Read-only diagnostic commands. Privileged ones use the full binary path and
# are matched by /etc/sudoers.d/monitor on each node.
# ---------------------------------------------------------------------------
DF = "/usr/bin/df -h -x tmpfs -x devtmpfs -x overlay -x squashfs"
JOURNAL = "sudo -n /usr/bin/journalctl -p err -b --no-pager -n 25"
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
GPU = (
    "/usr/bin/nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,"
    "memory.used,memory.total --format=csv,noheader,nounits"
)
# Guest (CT/VM) liveness, read-only. Scoped in sudoers to the `list` subcommand
# only — NOT blanket pct/qm (which could start/stop/destroy). pct on pve3 (LXCs:
# grafana/homepage/etc.), qm on QuarkyLab (wazuh VM).
PCT_LIST = "sudo -n /usr/sbin/pct list"
QM_LIST = "sudo -n /usr/sbin/qm list"
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
# Wazuh manager (SIEM, VM 104 on QuarkyLab, its own IP .184) — monitor SSHes in like
# any node; sudoers there is scoped to exactly `wazuh-control status`. Only the CORE
# daemons matter: clusterd/maild/agentlessd/integratord/dbd/csyslogd are disabled by
# default and legitimately show "not running", so we never alert on those.
WAZUH = "sudo -n /var/ossec/bin/wazuh-control status"
WAZUH_CORE = {"wazuh-analysisd", "wazuh-remoted", "wazuh-db",
              "wazuh-modulesd", "wazuh-syscheckd"}
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

# Verdict severity. SKIPPED ranks at 0 alongside OK deliberately: an untested service must
# never make the estate look unhealthy, so a skip cannot raise the overall verdict. It is
# surfaced separately as "NOT TESTED" rather than folded in, so it also cannot be mistaken
# for a passing test. Module-level so the ordering is testable rather than buried in main().
VERDICT_RANK = {"OK": 0, "SKIPPED": 0, "WARN": 1, "AUTH-FAIL": 2, "TIMEOUT": 2}

NODES = {
    "jarvis":    {"ip": None,             "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "gpu": GPU, "llm_router_conformance": LLM_ROUTER_CONFORMANCE}},
    "randy":     {"ip": "192.168.10.187", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "zpool": ZPOOL, "pbs": PBS, "backup_verify": BACKUP_VERIFY}},
    "quarkylab": {"ip": "192.168.10.179", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "zpool": ZPOOL, "gpu": GPU, "guests": QM_LIST}},
    "pve2":      {"ip": "192.168.10.204", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART}},
    "pve3":      {"ip": "192.168.10.201", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "guests": PCT_LIST, "prometheus": PROMETHEUS}},
    "pve4":      {"ip": "192.168.10.202", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART}},
    "pve5":      {"ip": "192.168.10.203", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART}},
    # Wazuh SIEM VM (.184) — manager daemon health (scoped sudo) + unprivileged df.
    "wazuh":     {"ip": "192.168.10.184", "checks": {"wazuh": WAZUH, "df": DF}},
    # Synthetic node: monitoring-service health probed locally from Jarvis (no SSH).
    "monitoring": {"ip": None,            "checks": {"grafana": GRAFANA, "loki": LOKI, "pihole": PIHOLE, "page_auth": AUTHGUARD, "console_auth": CONSOLE_AUTHGUARD, "llm_router": LLM_ROUTER, "console_backend": CONSOLE_BACKEND, "report_backend": REPORT_BACKEND, "openwebui_reach": OPENWEBUI_REACH, "console_transact": CONSOLE_TRANSACT, "net_config_change": NET_CFGCHG, "net_syslog_flow": NET_FLOW}},
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


def parse_journal(out):
    actionable, benign = _split_journal(out)
    low = "\n".join(actionable).lower()
    return {"error_lines": len(actionable),
            "benign_filtered": len(benign),
            "auth_failures": low.count("authentication failure") + low.count("failed password"),
            "service_failures": low.count("failed to start")}


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


def parse_wazuh(out):
    status = {}
    for line in out.splitlines():
        m = re.match(r"\s*(wazuh-[\w-]+)\s+(is running|not running)", line)
        if m:
            status[m.group(1)] = (m.group(2) == "is running")
    core_down = sorted(d for d in WAZUH_CORE if status.get(d) is not True)
    return {"running": sum(1 for v in status.values() if v), "total": len(status),
            "down": sorted(d for d, v in status.items() if not v),
            "core_down": core_down, "up": not core_down}


PARSERS = {"df": parse_df, "gpu": parse_gpu, "zpool": parse_zpool,
           "smart": parse_smart, "journal_errors": parse_journal, "pbs": parse_pbs,
           "backup_verify": parse_backup_verify,
           "guests": parse_guests, "grafana": parse_grafana,
           "prometheus": parse_prometheus, "loki": parse_loki, "pihole": parse_pihole,
           "wazuh": parse_wazuh, "page_auth": parse_page_auth,
           "console_auth": parse_page_auth, "llm_router": parse_llm_router,
           "console_backend": parse_llm_router, "report_backend": parse_llm_router,
           "openwebui_reach": parse_llm_router, "console_transact": parse_transact,
           "llm_router_conformance": parse_llm_router_conformance,
           "net_config_change": parse_netlog, "net_syslog_flow": parse_netlog}


def classify(name, rc, out):
    """Coarse health verdict; auth detection keys off the command's OWN output
    (sudo's "sudo:" stderr / ssh publickey errors), never on substrings that can
    appear inside journal/SMART log text."""
    low = out.lower()
    if rc == 124:
        return "TIMEOUT"
    for line in out.splitlines():
        s = line.strip().lower()
        if s.startswith("sudo:") and ("password is required" in s or "a terminal is required" in s or "not allowed" in s):
            return "AUTH-FAIL"
    if "permission denied (publickey" in low or "host key verification failed" in low:
        return "AUTH-FAIL"
    if name == "guests":
        if rc != 0:
            return "WARN"
        for _, gname, status in _guest_rows(out):
            if gname.lower() in MONITORING_GUESTS and status != "running":
                return "WARN"  # a monitoring guest is down
        return "OK"
    if name == "grafana":
        if rc != 0:
            return "WARN"  # endpoint unreachable / HTTP error
        return "OK" if re.search(r'"database"\s*:\s*"ok"', out) else "WARN"
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
        # `wazuh-control status` exits non-zero if ANY daemon (incl. optional ones
        # that are down by design) isn't running, so rc is not a health signal.
        # Judge only by the CORE daemons; auth/ssh failures are caught above.
        daemons = re.findall(r"(wazuh-[\w-]+)\s+(?:is running|not running)", out)
        if not daemons:
            return "WARN"  # no daemon status at all -> command didn't really run
        for m in re.finditer(r"(wazuh-[\w-]+)\s+not running", out):
            if m.group(1) in WAZUH_CORE:
                return "WARN"
        return "OK"
    if name == "backup_verify":
        data = _backup_verify_load(out)
        if data is None:
            return "WARN"  # report missing / unreadable / not JSON
        age_h = _backup_verify_age_h(data)
        if age_h is None or age_h > BACKUP_VERIFY_MAX_AGE_H:
            return "WARN"  # stale report => dead cron/timer on Ares
        return "OK" if data.get("overall") == "pass" else "WARN"
    if name == "smart":
        if "self-assessment test result: failed" in low or "failing_now" in low or "smart health status: fail" in low:
            return "WARN"
        return "OK"
    if name == "zpool":
        return "OK" if "all pools are healthy" in low else "WARN"
    if name == "journal_errors":
        return "OK"
    return "OK" if rc == 0 else "WARN"


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
            if name.endswith("_transact"):
                # Only record the trend when the probe actually ran. Writing 0 for a skip
                # would make "we didn't test" indistinguishable from "it failed" in the
                # history, and every trend built on it would be wrong.
                if m.get("functionally_verified") is not None:
                    flat[f"{host}.{name}.verified"] = 1 if m["functionally_verified"] else 0
            if name == "wazuh":
                flat[f"{host}.wazuh.up"] = 1 if m.get("up") else 0
                flat[f"{host}.wazuh.running"] = m.get("running")
            if name in ("page_auth", "console_auth"):
                flat[f"{host}.{name}.enforced"] = 1 if m.get("auth_enforced") else 0
            if name == "backup_verify":
                ok = m.get("present") and m.get("overall") == "pass" and not m.get("stale")
                flat[f"{host}.backup_verify.ok"] = 1 if ok else 0
                if m.get("age_hours") is not None:
                    flat[f"{host}.backup_verify.age_hours"] = m["age_hours"]
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


def main():
    started = datetime.now(timezone.utc)
    report = {"started": started.isoformat(), "runner": socket.gethostname(), "nodes": {}}
    worst = "OK"
    rank = VERDICT_RANK

    print(f"=== NetFRAME cluster health monitor — {started.isoformat()} ===")
    for host, cfg in NODES.items():
        ip = cfg["ip"]
        label = f"{host} (local)" if ip is None else f"{host} ({ip})"
        print(f"\n########## {label} ##########")
        node_result = {}
        for name, command in cfg["checks"].items():
            rc, out = run(ip, command)
            verdict = classify(name, rc, out)
            if rank[verdict] > rank[worst]:
                worst = verdict
            try:
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

    verdicts = {f"{h}.{n}": c["verdict"]
                for h, checks in report["nodes"].items() for n, c in checks.items()}
    append_history({"ts": started.isoformat(), "worst": worst,
                    "verdicts": verdicts, "metrics": flatten_metrics(report["nodes"])})

    return 1 if worst in ("AUTH-FAIL", "TIMEOUT") else 0


if __name__ == "__main__":
    sys.exit(main())
