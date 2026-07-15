#!/usr/bin/env python3
"""NetFRAME configuration-drift detector.

Read-only. Fingerprints key config surfaces on each node over the existing
read-only 'monitor' SSH path (no new credentials, no changes to the nodes):
  - interfaces: /etc/network/interfaces
  - ssh:        /etc/ssh/sshd_config + sshd_config.d/*.conf
  - sysctl:     /etc/sysctl.d/*.conf
It compares each fingerprint to a HUMAN-APPROVED baseline (context/config-baseline.json,
Jarvis-local). Drift = a category whose hash differs from baseline, i.e. a config
changed since it was last blessed. Legitimate changes are acknowledged by re-running
'set-baseline' (the human gate, mirroring the operational-memory promote step).

Usage:
  netframe_confdrift.py check          # default: report drift vs baseline
  netframe_confdrift.py set-baseline   # bless the current configs as the new baseline
"""
import datetime as dt
import json
import os
import subprocess
import sys

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
KEY = f"{BASE}/monitor_key"
BASELINE = f"{BASE}/context/config-baseline.json"
OUT = f"{BASE}/report-confdrift.md"
TIMEOUT = 15

# name -> ip (None = local Jarvis). Mirrors the collector's cluster nodes.
NODES = {
    "jarvis": None, "randy": "192.168.10.187", "quarkylab": "192.168.10.179",
    "pve2": "192.168.10.204", "pve3": "192.168.10.201",
    "pve4": "192.168.10.202", "pve5": "192.168.10.203",
}
# one command; emits 'category:sha256' lines. Missing files hash to empty -> stable.
FP_CMD = (
    'echo "interfaces:$(sha256sum < /etc/network/interfaces 2>/dev/null | cut -d\' \' -f1)"; '
    'echo "ssh:$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null '
    '| sha256sum | cut -d\' \' -f1)"; '
    'echo "sysctl:$(cat /etc/sysctl.d/*.conf 2>/dev/null | sha256sum | cut -d\' \' -f1)"'
)
SSH_OPTS = ["-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=accept-new"]


def fingerprint(ip):
    argv = ["bash", "-c", FP_CMD] if ip is None else ["ssh", *SSH_OPTS, f"monitor@{ip}", FP_CMD]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None
    if p.returncode != 0:
        return None
    fp = {}
    for line in p.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fp[k.strip()] = v.strip()
    return fp or None


def collect():
    return {name: fingerprint(ip) for name, ip in NODES.items()}


def load_baseline():
    if os.path.exists(BASELINE):
        try:
            return json.load(open(BASELINE))
        except ValueError:
            return {}
    return {}


def save_baseline(cur):
    os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
    payload = {"blessed": dt.datetime.now(dt.timezone.utc).isoformat(), "fingerprints": cur}
    with open(BASELINE, "w") as fh:
        json.dump(payload, fh, indent=2)


def write_report(lines):
    now = dt.datetime.now(dt.timezone.utc)
    report = (f"# NetFRAME Config-Drift Report\n\n_Generated {now.isoformat()} on Jarvis_\n\n---\n\n"
              + "\n".join(lines) + "\n")
    with open(OUT, "w") as fh:
        fh.write(report)


def cmd_check():
    base = load_baseline().get("fingerprints", {})
    cur = collect()
    if not base:
        save_baseline(cur)
        msg = "No baseline existed; established one from the current configs. Re-run to detect drift."
        print(msg)
        write_report([f"## Baseline established\n{msg}"])
        return
    drift, unreach = [], []
    for name, ip in NODES.items():
        c = cur.get(name)
        if c is None:
            unreach.append(name)
            continue
        b = base.get(name, {})
        for cat, h in c.items():
            if b.get(cat) and b[cat] != h:
                drift.append((name, cat))
    lines = ["## Configuration drift vs baseline"]
    if drift:
        lines.append(f"_baseline blessed {load_baseline().get('blessed', '?')}_\n")
        lines.append("| Node | Category | Status |")
        lines.append("|---|---|---|")
        for name, cat in drift:
            lines.append(f"| {name} | {cat} | **DRIFTED** since baseline |")
        lines.append("\nIf a listed change was intentional, bless it with "
                     "`netframe_confdrift.py set-baseline`. If not, investigate what changed.")
        print(f"CONFIG DRIFT: {len(drift)} category/node change(s) vs baseline.")
    else:
        lines.append("All node configs match the approved baseline (interfaces, ssh, sysctl). "
                     "No drift.")
        print("no config drift.")
    if unreach:
        lines.append(f"\n_Unreachable this run (not evaluated): {', '.join(unreach)}._")
    write_report(lines)


def cmd_set_baseline():
    cur = collect()
    reachable = {k: v for k, v in cur.items() if v is not None}
    save_baseline(cur)
    print(f"baseline blessed: {len(reachable)}/{len(NODES)} nodes fingerprinted -> {BASELINE}")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "set-baseline":
        cmd_set_baseline()
    elif cmd == "check":
        cmd_check()
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
