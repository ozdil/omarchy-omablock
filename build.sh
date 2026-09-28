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
/usr/bin/install -m 755 "${DIR}/omablock-engine" "${HOME}/.local/bin/omablock"
/usr/bin/install -m 755 "${DIR}/omablock-dashboard" "${HOME}/.local/bin/omablock-dashboard"
/usr/bin/install -m 755 "${DIR}/omablock-status" "${HOME}/.local/bin/omablock-status"

echo "omablock-engine compiled successfully into ~/.local/bin."
echo ""
echo "=== Optional System-Wide Sinkhole Helper ==="
echo "To enable system-level /etc/hosts sync and Polkit integration without password prompts,"
echo "install the system package using Arch Linux PKGBUILD:"
echo "    makepkg -si"
echo ""

if [[ -x /usr/bin/omarchy-restart-shell ]]; then
    echo "Reloading Omarchy shell..."
    /usr/bin/omarchy-restart-shell >/dev/null 2>&1 || true
fi

echo "OmaBlock setup is complete and ready."
