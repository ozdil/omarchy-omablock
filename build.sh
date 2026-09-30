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

# User state directory and installation manifest
STATE_DIR="${HOME}/.local/state/omarchy/omablock"
MANIFEST_FILE="${STATE_DIR}/install_manifest.json"
/usr/bin/install -d -m 700 "${STATE_DIR}"
/usr/bin/install -d -m 755 "${HOME}/.local/bin"

# Binaries to install
TARGET_BINARIES=("omablock-engine" "omablock" "omablock-dashboard" "omablock-status")

get_manifest_hash() {
    local target="$1"
    /usr/bin/python3 -c '
import json, sys
target = sys.argv[1]
manifest_path = sys.argv[2]
try:
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        files = data.get("files", {})
        if target in files:
            print(files[target])
            sys.exit(0)
        else:
            sys.exit(2)
except Exception:
    sys.exit(3)
' "${target}" "${MANIFEST_FILE}"
}

# Pre-installation ownership verification:
# Refuse to overwrite foreign files, symlinks, or tampered files not matching OmaBlock's manifest.
for bin_name in "${TARGET_BINARIES[@]}"; do
    target_path="${HOME}/.local/bin/${bin_name}"
    if [[ -e "${target_path}" || -L "${target_path}" ]]; then
        if [[ -L "${target_path}" ]]; then
            echo "Security Error: Target ${target_path} is a symlink. Refusing to overwrite foreign or symlinked file." >&2
            exit 1
        fi

        if [[ ! -f "${target_path}" ]]; then
            echo "Security Error: Target ${target_path} is not a regular file." >&2
            exit 1
        fi

        # If file exists, verify ownership and integrity via manifest
        if [[ -f "${MANIFEST_FILE}" ]]; then
            recorded_hash=""
            manifest_status=0
            recorded_hash=$(get_manifest_hash "${target_path}") || manifest_status=$?

            if [[ ${manifest_status} -eq 3 ]]; then
                echo "Security Error: Installation manifest at ${MANIFEST_FILE} is corrupt or unreadable." >&2
                exit 1
            elif [[ ${manifest_status} -eq 2 || -z "${recorded_hash}" ]]; then
                echo "Security Conflict: A pre-existing non-OmaBlock file exists at ${target_path}." >&2
                echo "Refusing to overwrite foreign user-managed executable." >&2
                exit 1
            elif [[ ${manifest_status} -ne 0 ]]; then
                echo "Security Error: Failed to query installation manifest." >&2
                exit 1
            fi

            current_hash=$(/usr/bin/sha256sum "${target_path}" 2>/dev/null | /usr/bin/awk '{print $1}')
            if [[ -z "${current_hash}" || "${current_hash}" != "${recorded_hash}" ]]; then
                echo "Security Conflict: File ${target_path} hash does not match installation manifest." >&2
                echo "Refusing to overwrite modified or untracked file." >&2
                exit 1
            fi
        else
            echo "Security Conflict: Target ${target_path} exists but no installation manifest was found." >&2
            echo "Refusing to overwrite untracked pre-existing file." >&2
            exit 1
        fi
    fi
done

# Install user-facing binaries in ~/.local/bin
/usr/bin/install -m 755 "${DIR}/omablock-engine" "${HOME}/.local/bin/omablock-engine"
/usr/bin/install -m 755 "${DIR}/omablock-engine" "${HOME}/.local/bin/omablock"
/usr/bin/install -m 755 "${DIR}/omablock-dashboard" "${HOME}/.local/bin/omablock-dashboard"
/usr/bin/install -m 755 "${DIR}/omablock-status" "${HOME}/.local/bin/omablock-status"

# Record install manifest with SHA-256 hashes to track exact files created by this installer
TMP_MANIFEST="$(/usr/bin/mktemp -p "${STATE_DIR}" .tmp_manifest.XXXXXX)"
chmod 600 "${TMP_MANIFEST}"

{
    echo "{"
    echo "  \"installer\": \"ozdil.omablock\","
    echo "  \"installed_at\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
    echo "  \"files\": {"
    first=true
    for bin_name in "${TARGET_BINARIES[@]}"; do
        target_path="${HOME}/.local/bin/${bin_name}"
        sha=$(/usr/bin/sha256sum "${target_path}" | /usr/bin/awk '{print $1}')
        if [ "$first" = true ]; then
            first=false
        else
            echo ","
        fi
        printf '    "%s": "%s"' "${target_path}" "${sha}"
    done
    echo ""
    echo "  }"
    echo "}"
} > "${TMP_MANIFEST}"

mv -f "${TMP_MANIFEST}" "${MANIFEST_FILE}"
chmod 600 "${MANIFEST_FILE}"

echo "omablock-engine compiled successfully and recorded in install manifest."
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
