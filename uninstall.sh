#!/bin/bash -p
set -euo pipefail

echo "=== OmaBlock Removal Script ==="
echo "Removing privileged helper and polkit policy (requires sudo privileges):"

if [[ -f /usr/bin/omablock-hosts-sync ]]; then
    # Clear any active OmaBlock entries before removal
    sudo /usr/bin/omablock-hosts-sync --clear || true
    sudo /usr/bin/rm -f /usr/bin/omablock-hosts-sync
fi

if [[ -f /usr/local/bin/omablock-hosts-sync ]]; then
    sudo /usr/bin/rm -f /usr/local/bin/omablock-hosts-sync
fi

if [[ -f /usr/share/polkit-1/actions/io.omarchy.omablock.policy ]]; then
    sudo /usr/bin/rm -f /usr/share/polkit-1/actions/io.omarchy.omablock.policy
fi

# Remove user binaries
/usr/bin/rm -f "${HOME}/.local/bin/omablock-engine" "${HOME}/.local/bin/omablock-dashboard" "${HOME}/.local/bin/omablock-status" "${HOME}/.local/bin/omablock" 2>/dev/null || true

echo "OmaBlock helper and binaries removed successfully."
