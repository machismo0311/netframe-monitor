#!/usr/bin/env bash
# NetFRAME monitor cycle: collect diagnostics, then have Jarvis's LLM interpret.
# Exits with the collector's status so `systemctl status` still surfaces
# AUTH-FAIL/TIMEOUT, while the interpreter always runs (|| true).
/usr/bin/python3 /opt/netframe-monitor/netframe_monitor.py
rc=$?
/usr/bin/python3 /opt/netframe-monitor/netframe_interpret.py || true
exit "$rc"
