#!/usr/bin/env python3
"""NetFRAME deterministic node-down alerter (Grafana-independent path).

The 2026-07-16 pve3 outage proved the alerting SPOF: Grafana died with the node
it should have alerted about, and Discord stayed silent. This module is the
redundant path: it runs in every 15-minute collector cycle on Jarvis, reads
last_run.json, and DMs the operator over the on-call bot's Discord token when a
node transitions to fully UNREACHABLE (every check) or recovers. It depends only
on Jarvis + the collector + Discord — none of the monitored infrastructure.

Deliberately NOT an LLM surface: messages are fixed templates carrying node
names and a timestamp, no model prose, so it sits outside the policy boundary
by construction (nothing to screen). It never executes anything.

Config (systemd EnvironmentFile /etc/netframe-alert.env, root 0600, gitignored;
also parsed directly as a fallback for manual runs):
  DISCORD_BOT_TOKEN  - the on-call bot's token (reused; bot is DM-only anyway)
  DISCORD_USER_ID    - the operator's Discord user id (allowlist-of-one)

State: context/alert-state.json holds the currently-down set; alerts fire only
on transitions, so a node stays quiet while it is *known* down. State is only
advanced when the DM actually sent (failed sends retry next cycle).
"""
import datetime as dt
import json
import os
import sys
import urllib.request

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
STATE_FILE = f"{BASE}/last_run.json"
ALERT_STATE = f"{BASE}/context/alert-state.json"
ENV_FILE = "/etc/netframe-alert.env"
API = "https://discord.com/api/v10"
TIMEOUT = 15


def compute_down(report):
    """Nodes where every check (at least one) came back UNREACHABLE."""
    down = []
    for host, checks in report.get("nodes", {}).items():
        if checks and all(c.get("verdict") == "UNREACHABLE" for c in checks.values()):
            down.append(host)
    return sorted(down)


def diff_state(prev_down, cur_down):
    """(newly_down, recovered) between two sorted lists."""
    p, c = set(prev_down), set(cur_down)
    return sorted(c - p), sorted(p - c)


def _load_env():
    tok = os.environ.get("DISCORD_BOT_TOKEN")
    uid = os.environ.get("DISCORD_USER_ID")
    if not (tok and uid) and os.path.exists(ENV_FILE):
        for line in open(ENV_FILE):
            line = line.strip()
            if line.startswith("DISCORD_BOT_TOKEN="):
                tok = tok or line.split("=", 1)[1]
            elif line.startswith("DISCORD_USER_ID="):
                uid = uid or line.split("=", 1)[1]
    return tok, uid


def _post(url, payload, token):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bot {token}",
                 "Content-Type": "application/json",
                 "User-Agent": "netframe-alert (jarvis, deterministic)"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.load(resp)


def send_dm(token, user_id, message):
    channel = _post(f"{API}/users/@me/channels", {"recipient_id": str(user_id)}, token)
    _post(f"{API}/channels/{channel['id']}/messages", {"content": message}, token)


def main():
    try:
        report = json.load(open(STATE_FILE))
    except (OSError, ValueError) as exc:
        print(f"netframe_alert: cannot read {STATE_FILE}: {exc}", file=sys.stderr)
        return 0  # collector problem; the dead-man alert owns that failure mode
    cur_down = compute_down(report)

    prev_down = []
    if os.path.exists(ALERT_STATE):
        try:
            prev_down = json.load(open(ALERT_STATE)).get("down", [])
        except ValueError:
            pass
    newly_down, recovered = diff_state(prev_down, cur_down)
    if not newly_down and not recovered:
        return 0

    token, uid = _load_env()
    if not (token and uid):
        print("netframe_alert: DISCORD_BOT_TOKEN/DISCORD_USER_ID not configured; "
              f"would have alerted: down={newly_down} recovered={recovered}")
        return 0

    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []
    for host in newly_down:
        n = len(report["nodes"][host])
        lines.append(f"🔴 **NODE DOWN: {host}** — all {n} health checks UNREACHABLE "
                     f"as of {ts} (netframe collector, Grafana-independent path).")
    for host in recovered:
        lines.append(f"🟢 **NODE RECOVERED: {host}** — answering again as of {ts}.")
    try:
        send_dm(token, uid, "\n".join(lines))
    except Exception as exc:  # noqa: BLE001 - alerting must not crash the cycle
        print(f"netframe_alert: Discord send failed ({exc}); will retry next cycle",
              file=sys.stderr)
        return 0  # state NOT advanced -> transition re-fires next run

    os.makedirs(os.path.dirname(ALERT_STATE), exist_ok=True)
    with open(ALERT_STATE, "w") as fh:
        json.dump({"down": cur_down, "updated": ts}, fh, indent=2)
    print(f"netframe_alert: sent — down={newly_down} recovered={recovered}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
