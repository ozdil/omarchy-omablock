#!/bin/bash
# End-to-end test of the privileged flow: engine -> sudo -> omablock-hosts-sync ->
# /etc/hosts and nftables. Runs as root inside private mount and network namespaces,
# with a copy of /etc bind-mounted over the real one, so the host is never touched:
#
#   sudo bash tests/e2e_privileged.sh target/debug/omablock-engine
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
# Always re-exec inside fresh mount and network namespaces; the bind mounts and nft
# tables below must never reach the host.
if [ "${OMABLOCK_E2E_NAMESPACED:-}" != 1 ]; then
    exec unshare --mount --propagation private --net env OMABLOCK_E2E_NAMESPACED=1 bash "$0" "$@"
fi

ENGINE="$(realpath "$1")"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"

mkdir -p "$WORK/etc" "$WORK/home"
cp -a /etc/. "$WORK/etc/" 2>/dev/null || true
printf '127.0.0.1 localhost\n10.0.0.5 nas.home\n' > "$WORK/etc/hosts"
mount --bind "$WORK/etc" /etc
mount -t tmpfs tmpfs /usr/local/bin
install -m 755 "$REPO/omablock-hosts-sync" /usr/local/bin/omablock-hosts-sync
mkdir -p /run/omablock && mount -t tmpfs tmpfs /run/omablock
export HOME="$WORK/home"

fail() { echo "FAIL: $*"; exit 1; }
run() { "$ENGINE" "$@" >/dev/null 2>&1 || fail "omablock-engine $* exited $?"; }
field() { "$ENGINE" --json | python3 -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {}, {'d': d}))" "$1"; }
sinks() { grep -c '^0\.0\.0\.0 ' /etc/hosts || true; }
has_table() { nft list tables 2>/dev/null | grep -qx "table inet $1"; }

run --enable
[ "$(sinks)" -gt 1000 ] || fail "enable wrote $(sinks) sinkhole entries"
grep -q '^10.0.0.5 nas.home$' /etc/hosts || fail "user entry lost on enable"
[ "$(field "d['active_rules']")" = "$(sinks)" ] || fail "active_rules does not match /etc/hosts"
echo "ok: enable ($(sinks) entries)"

# The builtin list contains ogads-pa.googleapis.com; Google's consoles need it to save
! grep -q ' ogads-pa\.googleapis\.com$' /etc/hosts || fail "essential Google endpoint blocked"
echo "ok: essential domains stay reachable"

run --whitelist-add doubleclick.net
! grep -q ' doubleclick\.net$' /etc/hosts || fail "whitelisted domain still blocked"
echo "ok: whitelist"

run --set-level ultimate
has_table omablock || fail "ultimate did not create the kernel table"
[ "$(field "d['kernel_status']['is_active']")" = True ] || fail "kernel status not active"
grep -q ' dns\.google$' /etc/hosts || fail "ultimate did not block DoH"
echo "ok: ultimate (kernel table, DoH)"

run --panic-blackout
has_table omablock_blackout || fail "blackout table missing"
[ "$(field "d['network_blackout_active']")" = True ] || fail "blackout not reported"
run --resume-network
! has_table omablock_blackout || fail "blackout table left after resume"
has_table omablock || fail "resume removed the kernel table"
echo "ok: blackout on/off"

run --set-level standard
! has_table omablock || fail "kernel table left after leaving ultimate"
! grep -q ' dns\.google$' /etc/hosts || fail "DoH still blocked after leaving ultimate"
echo "ok: standard"

# --pause schedules a systemd user timer when one is available; here it is not
"$ENGINE" --pause 1 >/dev/null 2>&1 || fail "pause exited $?"
[ "$(sinks)" = 0 ] || fail "pause left $(sinks) entries"
run --resume
[ "$(sinks)" -gt 1000 ] || fail "resume did not re-apply"
echo "ok: pause/resume"

run --restore-hosts
[ "$(cat /etc/hosts)" = "$(printf '127.0.0.1 localhost\n10.0.0.5 nas.home')" ] || fail "restore did not bring back the original hosts"
[ -f /etc/hosts.omablock.pre-restore ] || fail "pre-restore copy missing"
[ "$(field "d['enabled']")" = False ] || fail "protection still enabled after restore"
echo "ok: restore"

echo "e2e privileged flow: all checks passed"
