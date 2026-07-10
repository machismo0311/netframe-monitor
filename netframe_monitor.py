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

NODES = {
    "jarvis":    {"ip": None,             "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "gpu": GPU}},
    "randy":     {"ip": "192.168.10.187", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "zpool": ZPOOL, "pbs": PBS}},
    "quarkylab": {"ip": "192.168.10.179", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART, "zpool": ZPOOL, "gpu": GPU}},
    "pve2":      {"ip": "192.168.10.204", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART}},
    "pve3":      {"ip": "192.168.10.201", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART}},
    "pve4":      {"ip": "192.168.10.202", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART}},
    "pve5":      {"ip": "192.168.10.203", "checks": {"df": DF, "journal_errors": JOURNAL, "smart": SMART}},
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


def parse_journal(out):
    lines = [l for l in out.splitlines() if l.strip()]
    low = out.lower()
    return {"error_lines": len(lines),
            "auth_failures": low.count("authentication failure") + low.count("failed password"),
            "service_failures": low.count("failed to start")}


def parse_pbs(out):
    stores = [l for l in out.splitlines() if l and not l.startswith(("┌", "├", "└", "│ Name", "╞"))]
    return {"lines": len([l for l in out.splitlines() if l.strip()])}


PARSERS = {"df": parse_df, "gpu": parse_gpu, "zpool": parse_zpool,
           "smart": parse_smart, "journal_errors": parse_journal, "pbs": parse_pbs}


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
            node_result[name] = {"verdict": verdict, "rc": rc, "metrics": metrics,
                                 "raw_excerpt": out[:RAW_EXCERPT]}
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
