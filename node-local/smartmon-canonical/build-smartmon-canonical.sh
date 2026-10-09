#!/usr/bin/env bash
# PROPOSAL, SOURCE ONLY, not run by anything in this repository.
#
# Builds /usr/local/share/netframe/smartmon-canonical.sh from the PACKAGED smartmon.sh by
# replacing its one device-list line with `nfm-smart --targets`. Run as root on a node, after
# /usr/local/sbin/nfm-smart is installed and before the drop-in 10-netframe-canonical.conf.
#
# Fails closed: if the upstream line is not found exactly once (package update changed it), it
# writes nothing and exits 1, so the drop-in must not be installed and the packaged unit keeps
# running unchanged. Re-run after every prometheus-node-exporter-collectors upgrade.
set -u

src=/usr/share/prometheus-node-exporter-collectors/smartmon.sh
dst=/usr/local/share/netframe/smartmon-canonical.sh
# Literal text, deliberately unexpanded.
# shellcheck disable=SC2016
upstream_line='device_list="$(/usr/sbin/smartctl --scan-open | awk '"'"'/^\/dev/{print $1 "|" $3}'"'"')"'
# shellcheck disable=SC2016
canonical_line='device_list="$(/usr/local/sbin/nfm-smart --targets)"'

if [[ ! -r "$src" ]]; then
	echo "build-smartmon-canonical: $src not readable" >&2
	exit 1
fi
count=$(grep -cxF -- "$upstream_line" "$src")
if [[ "$count" != 1 ]]; then
	echo "build-smartmon-canonical: upstream device_list line found $count times, expected 1" >&2
	exit 1
fi
if ! /usr/local/sbin/nfm-smart --targets >/dev/null; then
	echo "build-smartmon-canonical: nfm-smart --targets failed" >&2
	exit 1
fi
install -d -m 0755 /usr/local/share/netframe
tmp=$(mktemp "$dst.XXXXXX")
# ENVIRON, not -v: awk -v would process the backslash in the literal and never match.
UP="$upstream_line" CAN="$canonical_line" \
	awk '$0 == ENVIRON["UP"] { print ENVIRON["CAN"]; next } { print }' "$src" >"$tmp"
chmod 0755 "$tmp"
mv -f "$tmp" "$dst"
echo "build-smartmon-canonical: wrote $dst"
