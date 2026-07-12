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
HISTORY_CAP = 300  # keep the most recent N runs for trend context

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

NODES = {
    "jarvis":    {"ip": None,             "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "gpu": GPU}},
    "randy":     {"ip": "192.168.10.187", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "zpool": ZPOOL, "pbs": PBS}},
    "quarkylab": {"ip": "192.168.10.179", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "zpool": ZPOOL, "gpu": GPU, "guests": QM_LIST}},
    "pve2":      {"ip": "192.168.10.204", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART}},
    "pve3":      {"ip": "192.168.10.201", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "guests": PCT_LIST, "prometheus": PROMETHEUS}},
    "pve4":      {"ip": "192.168.10.202", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART}},
    "pve5":      {"ip": "192.168.10.203", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART}},
    # Wazuh SIEM VM (.184) — manager daemon health (scoped sudo) + unprivileged df.
    "wazuh":     {"ip": "192.168.10.184", "checks": {"wazuh": WAZUH, "df": DF}},
    # Synthetic node: monitoring-service health probed locally from Jarvis (no SSH).
    "monitoring": {"ip": None,            "checks": {"grafana": GRAFANA, "loki": LOKI, "pihole": PIHOLE, "page_auth": AUTHGUARD}},
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
    for l in out.splitlines():
        if not l.strip():
            continue
        (benign if BENIGN_JOURNAL_RE.search(l) else actionable).append(l)
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
    stores = [l for l in out.splitlines() if l and not l.startswith(("┌", "├", "└", "│ Name", "╞"))]
    return {"lines": len([l for l in out.splitlines() if l.strip()])}


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


def parse_pihole(out):
    dns_ip, http_code, section = None, None, None
    for line in out.splitlines():
        s = line.strip()
        if s == "DNS:":
            section = "dns"; continue
        if s == "HTTP:":
            section = "http"; continue
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
           "guests": parse_guests, "grafana": parse_grafana,
           "prometheus": parse_prometheus, "loki": parse_loki, "pihole": parse_pihole,
           "wazuh": parse_wazuh, "page_auth": parse_page_auth}


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
    if name == "pihole":
        # OK when Pi-hole answers DNS (its core function).
        for line in out.splitlines():
            if re.match(r"\s*\d+\.\d+\.\d+\.\d+$", line.strip()):
                return "OK"
        return "WARN"
    if name == "page_auth":
        # 401 = NPM auth enforced (healthy). 200 = access list detached (public!).
        m = re.search(r"HTTP\s+(\d{3})", out)
        return "OK" if (m and m.group(1) == "401") else "WARN"
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
            if name in ("grafana", "prometheus", "loki", "pihole"):
                flat[f"{host}.{name}.up"] = 1 if m.get("up") else 0
            if name == "wazuh":
                flat[f"{host}.wazuh.up"] = 1 if m.get("up") else 0
                flat[f"{host}.wazuh.running"] = m.get("running")
            if name == "page_auth":
                flat[f"{host}.page_auth.enforced"] = 1 if m.get("auth_enforced") else 0
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
    rank = {"OK": 0, "WARN": 1, "AUTH-FAIL": 2, "TIMEOUT": 2}

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
