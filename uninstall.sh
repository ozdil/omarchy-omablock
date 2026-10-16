#!/bin/bash -p
set -euo pipefail

echo "=== OmaBlock User-Space Removal Script ==="

STATE_DIR="${HOME}/.local/state/omarchy/omablock"
MANIFEST_FILE="${STATE_DIR}/install_manifest.json"

# Turn the shield and panic blackout off first so /etc/hosts, the nftables tables and the browser
# DoH policies are restored while the engine and helper are still installed.
for engine in "${HOME}/.local/bin/omablock-engine" /usr/bin/omablock-engine; do
    if [[ -x "${engine}" && ! -L "${engine}" ]]; then
        echo "Disabling OmaBlock shield and restoring system DNS..."
        "${engine}" --disable || echo "Warning: could not disable the shield; run 'omablock-hosts-sync --clear' as root." >&2
        # --disable only clears the inet omablock table; panic blackout lives in its own table.
        if "${engine}" --json 2>/dev/null | /usr/bin/grep -Eq '"network_blackout_active": *true'; then
            echo "Lifting panic blackout..."
            "${engine}" --resume-network || echo "Warning: could not lift panic blackout; run 'omablock-hosts-sync --blackout-off' as root." >&2
        fi
        break
    fi
done

if [[ ! -f "${MANIFEST_FILE}" ]]; then
    echo "Notice: No OmaBlock installation manifest found at ${MANIFEST_FILE}."
    echo "Skipping ~/.local/bin deletion to preserve user-managed files."
else
    echo "Verifying OmaBlock ownership from install manifest..."
    # Parse installed files from manifest safely using Python json parser
    manifest_entries=""
    if ! manifest_entries=$(/usr/bin/python3 -c '
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
for path, digest in data.get("files", {}).items():
    print(f"{path}\t{digest}")
' "${MANIFEST_FILE}" 2>/dev/null); then
        echo "Error: installation manifest is unreadable; keeping it and all files untouched." >&2
        exit 1
    fi

    kept_files=0
    while IFS=$'\t' read -r file_path recorded_hash; do
        if [[ -z "${file_path}" || -z "${recorded_hash}" ]]; then
            continue
        fi

        if [[ -e "${file_path}" || -L "${file_path}" ]]; then
            if [[ -L "${file_path}" ]]; then
                echo "Warning: ${file_path} is a symlink. Skipping deletion to preserve user link." >&2
                kept_files=$((kept_files + 1))
                continue
            fi
            current_hash=$(/usr/bin/sha256sum "${file_path}" 2>/dev/null | /usr/bin/awk '{print $1}' || echo "")
            if [[ "${current_hash}" == "${recorded_hash}" ]]; then
                echo "Verified OmaBlock binary: ${file_path}. Removing..."
                /usr/bin/rm -f "${file_path}"
            else
                echo "Notice: ${file_path} does not match install hash (modified or replaced). Preserving file." >&2
                kept_files=$((kept_files + 1))
            fi
        fi
    done <<< "${manifest_entries}"

    if [[ ${kept_files} -eq 0 ]]; then
        /usr/bin/rm -f "${MANIFEST_FILE}"
        echo "Installation manifest cleaned."
    else
        # Keeping the manifest lets a later build.sh run recognise these paths.
        echo "Notice: ${kept_files} file(s) preserved; keeping ${MANIFEST_FILE}." >&2
    fi
fi

echo "If you installed the system helper package via makepkg/pacman, remove it using:"
echo "    sudo pacman -R omarchy-omablock"
echo "OmaBlock removal completed."
