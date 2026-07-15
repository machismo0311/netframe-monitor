#!/usr/bin/env bash
# NetFRAME monitor cycle: collect diagnostics, then have Jarvis's LLM interpret.
# Exits with the collector's status so `systemctl status` still surfaces
# AUTH-FAIL/TIMEOUT, while the interpreter always runs (|| true).
/usr/bin/python3 /opt/netframe-monitor/netframe_monitor.py
rc=$?
/usr/bin/python3 /opt/netframe-monitor/netframe_interpret.py || true
# Rebuild the unified memory dashboard (index.html) from all reports + the ledger.
/usr/bin/python3 /opt/netframe-monitor/netframe_web.py || true
# Freshness heartbeat for the Grafana dead-man alert (JAR-02): if this stops
# updating, NetframeMonitorStale fires. Written atomically for the scraper.
textfile_dir=/var/lib/prometheus/node-exporter
if [[ -d "$textfile_dir" ]]; then
	{
		echo "# HELP netframe_last_run_timestamp_seconds Unix time of the last completed netframe-run cycle."
		echo "# TYPE netframe_last_run_timestamp_seconds gauge"
		echo "netframe_last_run_timestamp_seconds $(date +%s)"
	} > "$textfile_dir/netframe.prom.$$" && mv "$textfile_dir/netframe.prom.$$" "$textfile_dir/netframe.prom"
fi
exit "$rc"
