#!/bin/bash -p
set -euo pipefail

# Immediate rejection of loader injection
if [ -n "${LD_PRELOAD:-}" ] || [ -n "${LD_LIBRARY_PATH:-}" ]; then
    echo "Security Error: Prohibited loader control variable detected" >&2
    exit 1
fi

DIR="$(cd "$(/usr/bin/dirname "$(/usr/bin/realpath "${BASH_SOURCE[0]}")")" && /usr/bin/pwd)"
cd "$DIR"

CARGO_BIN=""
if [[ -x /usr/bin/cargo ]]; then
    CARGO_BIN="/usr/bin/cargo"
elif [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    CARGO_BIN="${HOME}/.cargo/bin/cargo"
else
    echo "Error: cargo binary not found" >&2
    exit 1
fi

echo "Building omablock-engine from source..."
TMP_BUILD_DIR="$(/usr/bin/mktemp -d -t omablock-build.XXXXXX)"
cleanup() {
    /usr/bin/rm -rf "${TMP_BUILD_DIR}"
}
trap cleanup EXIT

"${CARGO_BIN}" build --release --locked --target-dir "${TMP_BUILD_DIR}"
/usr/bin/install -m 755 "${TMP_BUILD_DIR}/release/omablock-engine" "${DIR}/omablock-engine"

# Install user-facing binaries in ~/.local/bin
/usr/bin/install -d -m 755 "${HOME}/.local/bin"
/usr/bin/install -m 755 "${DIR}/omablock-engine" "${HOME}/.local/bin/omablock-engine"
/usr/bin/install -m 755 "${DIR}/omablock-dashboard" "${HOME}/.local/bin/omablock-dashboard"
/usr/bin/install -m 755 "${DIR}/omablock-status" "${HOME}/.local/bin/omablock-status"

echo "omablock-engine compiled successfully."
echo ""
echo "=== Privileged Helper Installation ==="
echo "OmaBlock requires omablock-hosts-sync and polkit policy to modify /etc/hosts without raw password prompts."
echo "Installing helper and polkit policy (requires sudo privileges):"

sudo /usr/bin/install -m 755 "${DIR}/omablock-hosts-sync" /usr/bin/omablock-hosts-sync
sudo /usr/bin/install -m 644 "${DIR}/assets/io.omarchy.omablock.policy" /usr/share/polkit-1/actions/io.omarchy.omablock.policy

if [[ -x /usr/bin/omarchy-restart-shell ]]; then
    echo "Reloading Omarchy shell..."
    /usr/bin/omarchy-restart-shell >/dev/null 2>&1 || true
fi

echo "OmaBlock setup is complete and ready."
