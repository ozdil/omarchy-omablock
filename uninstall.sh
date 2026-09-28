#!/bin/bash -p
set -euo pipefail

echo "=== OmaBlock Removal Script ==="
echo "Safely removing OmaBlock helper and polkit policy (requires sudo privileges):"

HELPER_BIN="/usr/bin/omablock-hosts-sync"
ALT_HELPER_BIN="/usr/local/bin/omablock-hosts-sync"
POLICY_TARGET="/usr/share/polkit-1/actions/io.omarchy.omablock.policy"
HELPER_SIG="OMABLOCK_HELPER_SIGNATURE = \"7f8b9e6a-omablock-hosts-sync-helper-v1\""
POLICY_ID="io.omarchy.omablock.sync-hosts"

remove_helper_safely() {
    local target="$1"
    if [[ -e "${target}" || -L "${target}" ]]; then
        if [[ -L "${target}" ]]; then
            echo "Warning: ${target} is a symlink. Skipping deletion to preserve user target." >&2
            return
        fi
        if grep -q "${HELPER_SIG}" "${target}" 2>/dev/null; then
            echo "Confirmed OmaBlock ownership on ${target}. Removing..."
            sudo "${target}" --clear || true
            sudo /usr/bin/rm -f "${target}"
        else
            echo "Notice: ${target} does not contain OmaBlock helper signature. Preserving administrator file." >&2
        fi
    fi
}

remove_policy_safely() {
    local target="$1"
    if [[ -e "${target}" || -L "${target}" ]]; then
        if [[ -L "${target}" ]]; then
            echo "Warning: ${target} is a symlink. Skipping deletion to preserve user target." >&2
            return
        fi
        if grep -q "${POLICY_ID}" "${target}" 2>/dev/null; then
            echo "Confirmed OmaBlock ownership on ${target}. Removing..."
            sudo /usr/bin/rm -f "${target}"
        else
            echo "Notice: ${target} does not contain OmaBlock policy identifier. Preserving file." >&2
        fi
    fi
}

remove_helper_safely "${HELPER_BIN}"
remove_helper_safely "${ALT_HELPER_BIN}"
remove_policy_safely "${POLICY_TARGET}"

# Remove user binaries
/usr/bin/rm -f "${HOME}/.local/bin/omablock-engine" "${HOME}/.local/bin/omablock-dashboard" "${HOME}/.local/bin/omablock-status" "${HOME}/.local/bin/omablock" 2>/dev/null || true

echo "OmaBlock safe removal process completed."
