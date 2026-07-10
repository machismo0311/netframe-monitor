#!/bin/bash
# netframe-8808-lock: restrict tcp/8808 (NetFRAME report page) to NPM + localhost only.
# The report is meant to be reached ONLY through nginx-proxy-manager (which enforces
# Basic auth via the "Homepage Auth" access list). This blocks direct LAN/tailnet
# access to the unauthenticated backend. Scoped strictly to tcp/8808 - no other
# service is affected. Managed by netframe-8808-lock.service (idempotent).
port=8808
npm=192.168.10.181

# Remove any prior copies of our rules so re-runs don't stack duplicates.
while iptables -C INPUT -p tcp --dport "$port" -s 127.0.0.1 -j ACCEPT 2>/dev/null; do
	iptables -D INPUT -p tcp --dport "$port" -s 127.0.0.1 -j ACCEPT
done
while iptables -C INPUT -p tcp --dport "$port" -s "$npm" -j ACCEPT 2>/dev/null; do
	iptables -D INPUT -p tcp --dport "$port" -s "$npm" -j ACCEPT
done
while iptables -C INPUT -p tcp --dport "$port" -j DROP 2>/dev/null; do
	iptables -D INPUT -p tcp --dport "$port" -j DROP
done

# Insert in priority order (last insert ends up on top):
iptables -I INPUT 1 -p tcp --dport "$port" -j DROP
iptables -I INPUT 1 -p tcp --dport "$port" -s "$npm" -j ACCEPT
iptables -I INPUT 1 -p tcp --dport "$port" -s 127.0.0.1 -j ACCEPT
