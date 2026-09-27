#!/bin/bash
# netframe-8808-lock: restrict tcp/8808 (NetFRAME report page) to NPM + localhost only.
# The report is meant to be reached ONLY through nginx-proxy-manager (which enforces
# Basic auth via the "Homepage Auth" access list). This blocks direct LAN/tailnet
# access to the unauthenticated backend. Scoped strictly to tcp/8808 - no other
# service is affected. Managed by netframe-8808-lock.service (idempotent).
#
# THE TAILNET HALF OF THAT CLAIM IS NOW ACTUALLY ENFORCED (2026-09-27). Until today it was
# false: the filter-table DROP below is unreachable for tailnet traffic, because ts-input
# ACCEPTs tailscale0 first. Measured from a real tailnet peer, tcp/8808 answered HTTP 200
# with no challenge. The raw-table rule added further down closes it. See the block at
# TS_IF/TS_TAG for the placement evidence.
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

# --- the tailnet denial, and why it lives in the RAW table --------------------------------------
# MEASURED 2026-09-27. `-j ts-input` is INPUT rule 1 and `ts-input` rule 2 is an unconditional
# `-i tailscale0 -j ACCEPT`. An ACCEPT inside a user chain is terminal for the whole filter table,
# so NO rule placed later in INPUT can restrict tailnet access to this port. Two filter-table
# placements were evaluated and both are fragile:
#
#   * a NetFRAME rule inserted BEFORE the `-j ts-input` jump loses the position race. At the
#     2026-09-25 boot all three lock units started and finished at 10:41:31 and tailscaled logged
#     "Reconfig: configuring router" after them, yet the jump still sits at INPUT position 1 above
#     every lock rule. tailscaled re-asserts position 1 after other writers insert there.
#   * rules placed INSIDE ts-input are destroyed on every tailscaled bring-up, which logs
#     "Clearing router settings..." and recreates its own chains.
#
# The raw table's PREROUTING chain runs BEFORE the filter table, so a DROP there cannot be
# pre-empted by ts-input and needs no ordering contest with any other writer. It is owned by
# nothing on this host: raw is empty in both IPv4 and IPv6 (policies only), carries no PVEFW
# chains, and the nft ruleset is empty (iptables 1.8.11 legacy throughout).
#
# This service listens on 0.0.0.0 only, so no ip6tables rule is needed: an IPv6 tailnet peer has
# nothing to connect to. The rule matches the interface by NAME, so it is valid before tailscale0
# exists and survives the interface coming and going.
TS_IF="${NFM_TS_IF:-tailscale0}"
TS_TAG="NFM-8808-TAILNET-DENY"

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

# The tailnet denial spec, and the raw-table probe/mutate helpers. Same discipline as the filter
# path: bounded -w through ipt(), the probe classified instead of having its stderr discarded.
ts_spec() { echo -i "$TS_IF" -p tcp --dport "$port" -m comment --comment "$TS_TAG" -j DROP; }

ts_present() {
	local out rc=0
	# shellcheck disable=SC2086
	out=$(ipt -t raw -C PREROUTING $1 2>&1) || rc=$?
	case "$rc" in
	0) return 0 ;;
	1) return 1 ;;
	*)
		echo "netframe-8808-lock: raw probe failed (rc=$rc), not treating as absent: $out" >&2
		return 2
		;;
	esac
}

ts_remove_all() {
	local rc=0 prc n=0
	while true; do
		if [ "$n" -ge "${NFM_MAX_PASSES:-20}" ]; then
			echo "netframe-8808-lock: raw rule still present after $n delete(s), refusing to spin" >&2
			return 1
		fi
		n=$((n + 1))
		prc=0
		ts_present "$1" || prc=$?
		case "$prc" in
		0) ;;
		1) break ;;
		*)
			rc=1
			break
			;;
		esac
		# shellcheck disable=SC2086
		ipt -t raw -D PREROUTING $1 || {
			rc=1
			break
		}
	done
	return "$rc"
}

ts_insert() {
	# shellcheck disable=SC2086
	ipt -t raw -I PREROUTING 1 $1
}

# "rule absent" is normal idempotent control flow; a LOCK DENIAL is not. Discarding stderr made
# them the same branch, which is how a denied probe became "absent" and then stacked a duplicate.
# Classified: 0 present, 1 absent, 2 a real error, reported rather than swallowed. Brought into
# line with the raw-table probe added 2026-09-27 so both halves of this unit behave identically.
present() {
	local out rc=0
	# shellcheck disable=SC2086
	out=$(ipt -C "$CHAIN" $1 2>&1) || rc=$?
	case "$rc" in
	0) return 0 ;;
	1) return 1 ;;
	*)
		echo "netframe-8808-lock: probe failed (rc=$rc), not treating as absent: $out" >&2
		return 2
		;;
	esac
}

# Both removal loops are bounded. A delete that reports success without actually removing the rule
# would otherwise spin until the aggregate deadline: measured 2026-09-27 against a fake whose
# missing chain returned 0, the loop consumed the whole 45s budget. The bound turns that into an
# immediate, diagnosable failure. MAX_PASSES is far above any real duplicate count.
MAX_PASSES="${NFM_MAX_PASSES:-20}"

remove_all_copies() {
	local rc=0 prc n=0
	while true; do
		if [ "$n" -ge "$MAX_PASSES" ]; then
			echo "netframe-8808-lock: still present after $n delete(s), refusing to spin: $1" >&2
			return 1
		fi
		n=$((n + 1))
		prc=0
		present "$1" || prc=$?
		case "$prc" in
		0) ;;
		1) break ;;
		*)
			rc=1
			break
			;;
		esac
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
	local ts_dump n_ts n_ts_port
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

	# The tailnet denial in the raw table. Ordering needs no assertion here: raw PREROUTING runs
	# before the filter table by construction, so this rule is always evaluated before ts-input.
	ts_dump=$(ipt -t raw -S PREROUTING) || {
		echo "INVARIANT: could not read raw PREROUTING" >&2
		return 1
	}
	n_ts=$(printf '%s\n' "$ts_dump" | grep -c -- "$TS_TAG" || true)
	n_ts_port=$(printf '%s\n' "$ts_dump" | grep -c -- "--dport $port " || true)
	[ "$n_ts" = 1 ] || {
		echo "INVARIANT: raw PREROUTING has $n_ts rule(s) tagged $TS_TAG, want exactly 1" >&2
		bad=1
	}
	[ "$n_ts_port" = 1 ] || {
		echo "INVARIANT: $n_ts_port raw PREROUTING rule(s) touch dport $port, want exactly 1" >&2
		bad=1
	}
	ts_present "$(ts_spec)" || {
		echo "INVARIANT: the tailnet DROP for $TS_IF tcp/$port is absent from raw PREROUTING" >&2
		bad=1
	}
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
ts_remove_all "$(ts_spec)" || mutate_rc=1
ts_insert "$(ts_spec)" || mutate_rc=1

if verify_invariant && [ "$mutate_rc" = 0 ]; then
	echo "netframe-8808-lock: tcp/$port restricted to 127.0.0.1 and $npm; direct $TS_IF denied"
	exit 0
fi

echo "netframe-8808-lock: FAILED to establish the tcp/$port policy (mutate_rc=$mutate_rc)." >&2
echo "netframe-8808-lock: state left as-is deliberately; a re-run repairs it." >&2
exit 1
