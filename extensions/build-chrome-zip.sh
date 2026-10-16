#!/bin/bash -p
# Builds the Chrome Web Store upload package from extensions/chrome.
# - names the zip after the manifest version
# - leaves out store listing images (screenshot, promo, store icon)
# - strips the "key" field, which the Web Store rejects in uploads
set -euo pipefail

DIR="$(cd "$(/usr/bin/dirname "$(/usr/bin/realpath "${BASH_SOURCE[0]}")")" && /usr/bin/pwd)"
SRC="${DIR}/chrome"
OUT_DIR="${DIR}/dist"

/usr/bin/python3 -I - "${SRC}" "${OUT_DIR}" <<'PY'
import json, os, sys, zipfile

src, out_dir = sys.argv[1], sys.argv[2]
excluded = {"screenshot-1280x800.png", "promo-440x280.png", "icons/store-icon-128.png"}

with open(os.path.join(src, "manifest.json"), encoding="utf-8") as f:
    manifest = json.load(f)
manifest.pop("key", None)
version = manifest["version"]

os.makedirs(out_dir, exist_ok=True)
target = os.path.join(out_dir, f"omablock-chrome-bridge-v{version}.zip")
with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("manifest.json", json.dumps(manifest, indent=2) + "\n")
    for root, _dirs, files in os.walk(src):
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, src)
            if rel == "manifest.json" or rel in excluded:
                continue
            zf.write(path, rel)
print(target)
PY
