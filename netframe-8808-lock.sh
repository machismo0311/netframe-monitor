#!/bin/bash
# netframe-8808-lock: restrict tcp/8808 (NetFRAME report page) to NPM + localhost only.
# The report is meant to be reached ONLY through nginx-proxy-manager (which enforces
# Basic auth via the "Homepage Auth" access list). This blocks direct LAN/tailnet
# access to the unauthenticated backend. Scoped strictly to tcp/8808 - no other
# service is affected. Managed by netframe-8808-lock.service (idempotent).
#
# BOUNDED XTABLES WAIT (2026-09-26). Measured: this unit lost the /run/xtables.lock race on two of
# three retained boots, exiting 4 with "Another app is currently holding the xtables lock". On boot
# 2026-09-24T23:57 ALL THREE inserts failed, so tcp/8808 was left with no rules at all, i.e. the
# unauthenticated backend was fully exposed. pve-firewall is ruled out as the holder (it starts
# after the failures); tailscaled's router reconfiguration brackets both failures and is the
# likeliest holder, though unproven. Every call now passes -w so iptables waits for the lock.
#
# NO SILENT PARTIAL APPLICATION (2026-09-26). The old script had no error handling, so a run whose
# LAST insert happened to win reported success with only part of the policy in place. The complete
# invariant is now verified at the end and a shortfall exits nonzero with the exact reason.
#
# DELIBERATELY NO ROLLBACK ON PARTIAL FAILURE. Undoing a partial application would mean removing the
# DROP, leaving the unauthenticated backend open to the LAN. Failing loudly with the partial state
# intact is the safer end state, and a re-run repairs it because this script is idempotent.
set -eu

IPT="${NFM_IPT:-/usr/sbin/iptables}"
WAIT_SECONDS="${NFM_IPT_WAIT:-10}"
# The -w bound is PER CALL, and a full run makes up to ten calls, so an aggregate deadline is
# needed too: without one, a permanently held lock would take 10 x 10s and systemd would SIGTERM
# the unit mid-application at TimeoutStartSec (90s default), which is exactly the partial state
# this script exists to avoid. 45s leaves ample headroom and is ~28x the longest contention window
# measured in Phase 0 (tailscaled's ~1.6s router phase).
DEADLINE_SECONDS="${NFM_IPT_DEADLINE:-45}"
port="${NFM_8808_PORT:-8808}"
npm="${NFM_8808_NPM:-192.168.10.181}"
CHAIN=INPUT
STARTED=$SECONDS

# Every call waits for the lock, but never past the aggregate deadline, so the invariant check at
# the end is always reached and the outcome is always reported.
ipt() {
	local remaining wait
	remaining=$((DEADLINE_SECONDS - (SECONDS - STARTED)))
	if [ "$remaining" -le 0 ]; then
		echo "netframe-8808-lock: aggregate ${DEADLINE_SECONDS}s deadline exceeded, giving up" >&2
		return 4
	fi
	wait="$WAIT_SECONDS"
	[ "$wait" -le "$remaining" ] || wait="$remaining"
	"$IPT" -w "$wait" "$@"
}

# The three rule specs this unit owns, without the chain. Order below is the required order in the
# chain: both ACCEPTs must sit above the DROP.
spec_local() { echo -p tcp --dport "$port" -s 127.0.0.1 -j ACCEPT; }
spec_npm() { echo -p tcp --dport "$port" -s "$npm" -j ACCEPT; }
spec_drop() { echo -p tcp --dport "$port" -j DROP; }

# "rule absent" is normal idempotent control flow, so -C runs inside a conditional where its
# nonzero exit is expected and cannot trip set -e.
present() {
	# shellcheck disable=SC2086
	ipt -C "$CHAIN" $1 2>/dev/null
}

remove_all_copies() {
	local rc=0
	while present "$1"; do
		# shellcheck disable=SC2086
		ipt -D "$CHAIN" $1 || {
			rc=1
			break
		}
	done
	return "$rc"
}

insert_top() {
	# shellcheck disable=SC2086
	ipt -I "$CHAIN" 1 $1
}

# Canonical forms as iptables -S prints them, used to count and to prove ordering.
canon_local() { echo "-s 127.0.0.1/32 -p tcp -m tcp --dport $port -j ACCEPT"; }
canon_npm() { echo "-s $npm/32 -p tcp -m tcp --dport $port -j ACCEPT"; }
canon_drop() { echo "-p tcp -m tcp --dport $port -j DROP"; }

# The complete invariant. Anything short of it is a failure: a missing rule, a duplicate, an extra
# rule touching the port (broader exposure), or the DROP sitting above either ACCEPT.
verify_invariant() {
	local dump bad=0
	local n_local n_npm n_drop total i_local i_npm i_drop
	dump=$(ipt -S "$CHAIN")

	n_local=$(printf '%s\n' "$dump" | grep -c -F -- "$(canon_local)" || true)
	n_npm=$(printf '%s\n' "$dump" | grep -c -F -- "$(canon_npm)" || true)
	n_drop=$(printf '%s\n' "$dump" | grep -c -F -- "$(canon_drop)" || true)
	total=$(printf '%s\n' "$dump" | grep -c -- "--dport $port " || true)

	[ "$n_local" = 1 ] || {
		echo "INVARIANT: localhost ACCEPT count is $n_local, want exactly 1" >&2
		bad=1
	}
	[ "$n_npm" = 1 ] || {
		echo "INVARIANT: $npm ACCEPT count is $n_npm, want exactly 1" >&2
		bad=1
	}
	[ "$n_drop" = 1 ] || {
		echo "INVARIANT: DROP count is $n_drop, want exactly 1" >&2
		bad=1
	}
	[ "$total" = 3 ] || {
		echo "INVARIANT: $total rules touch dport $port, want exactly 3 (no broader exposure)" >&2
		bad=1
	}

	i_local=$(printf '%s\n' "$dump" | grep -n -F -- "$(canon_local)" | cut -d: -f1 | head -1)
	i_npm=$(printf '%s\n' "$dump" | grep -n -F -- "$(canon_npm)" | cut -d: -f1 | head -1)
	i_drop=$(printf '%s\n' "$dump" | grep -n -F -- "$(canon_drop)" | cut -d: -f1 | head -1)
	if [ -n "$i_local" ] && [ -n "$i_drop" ] && [ "$i_local" -gt "$i_drop" ]; then
		echo "INVARIANT: localhost ACCEPT (line $i_local) is below DROP (line $i_drop)" >&2
		bad=1
	fi
	if [ -n "$i_npm" ] && [ -n "$i_drop" ] && [ "$i_npm" -gt "$i_drop" ]; then
		echo "INVARIANT: $npm ACCEPT (line $i_npm) is below DROP (line $i_drop)" >&2
		bad=1
	fi
	return "$bad"
}

# Fast path: if the policy is already exactly right, change nothing at all.
if verify_invariant 2>/dev/null; then
	echo "netframe-8808-lock: policy already correct for tcp/$port"
	exit 0
fi

# Otherwise normalise. Every mutation's result is captured deliberately rather than aborting, so the
# invariant check below always runs and always reports what is actually wrong.
mutate_rc=0
remove_all_copies "$(spec_local)" || mutate_rc=1
remove_all_copies "$(spec_npm)" || mutate_rc=1
remove_all_copies "$(spec_drop)" || mutate_rc=1
insert_top "$(spec_drop)" || mutate_rc=1
insert_top "$(spec_npm)" || mutate_rc=1
insert_top "$(spec_local)" || mutate_rc=1

if verify_invariant && [ "$mutate_rc" = 0 ]; then
	echo "netframe-8808-lock: tcp/$port restricted to 127.0.0.1 and $npm"
	exit 0
fi

echo "netframe-8808-lock: FAILED to establish the tcp/$port policy (mutate_rc=$mutate_rc)." >&2
echo "netframe-8808-lock: state left as-is deliberately; a re-run repairs it." >&2
exit 1
