#!/bin/bash -p
set -euo pipefail

echo "=== OmaBlock User-Space Removal Script ==="
echo "Removing user-space binaries from ~/.local/bin..."

# Remove user binaries
/usr/bin/rm -f "${HOME}/.local/bin/omablock-engine" "${HOME}/.local/bin/omablock-dashboard" "${HOME}/.local/bin/omablock-status" "${HOME}/.local/bin/omablock" 2>/dev/null || true

echo "User-space binaries removed."
echo "If you installed the system helper package via makepkg/pacman, remove it using:"
echo "    sudo pacman -R omarchy-omablock"
echo "OmaBlock removal completed."
