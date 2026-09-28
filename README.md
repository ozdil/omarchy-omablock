# OmaBlock - Zero-Latency AdBlocker and Privacy Shield for Omarchy Linux

[![Omarchy Verified Plugin](https://img.shields.io/badge/Omarchy-Verified_Plugin-22c55e?style=for-the-badge&logo=omarchy)](https://github.com/ozdil)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy_Me_A_Coffee-Support_Development-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ozdil)

Kernel-level ad, tracker, and telemetry sinkhole plugin engineered for Omarchy Linux.

Author: Ozan Ozdil (ozdil)  
License: MIT  
Plugin ID: ozdil.omablock

---

## Features

- Zero Latency (< 0.1ms): Leverages atomic, kernel-level DNS sinkhole routing (`0.0.0.0`) without middleman proxy overhead or battery drain.
- Military-Grade HANCORE Defense: Deep integration of self-defense features including Self-Integrity Verification (SHA-256 binary hashing) and `prctl(PR_SET_DUMPABLE, 0)` anti-tamper.
- Advanced Kernel Blackout: Panic Blackout mode and Zero-Trust egress lockdown (drops non-loopback DNS 53/853 with TCP RST/ICMP admin-prohibited) for immediate threat containment.
- AI-Powered Threat Detection: Integrated IDN Homograph and Punycode spoofing radar via advanced DGA Classification engine to stop zero-day phishing typosquatting.
- 79,500+ Curated Rules: Pre-bundled offline database with one-click online synchronization against StevenBlack Unified and EasyPrivacy upstream blocklists.
- Fine-Grained Category Filtering:
  - Commercial Ads: DoubleClick, PageAd, Criteo, Taboola, Outbrain, popups, and video advertising networks.
  - Telemetry and Surveillance: Operating system, analytics, and third-party tracking beacons.
  - Malware and Phishing: Known command-and-control endpoints, cryptominers, and malicious domains.
  - Social Network Trackers: Third-party pixel trackers, audience measurement, and social widgets.
- Live Shield Verification: In-panel live resolution diagnostics to verify protection in real time.
- Custom Allow and Deny Lists: Instantly whitelist or blacklist specific domains with zero DNS downtime.
- Hardware Armor Control: Toggle USB access instantly through UI directly integrated with system state files.
- Monochrome Design: Native Omarchy UI styling adhering strictly to typography standards and color palette rules.
- Hardened Rust Engine: Strict regex sanitization, safe atomic file replacement, bounded memory limits, and zeroize-secured memory buffers.

---

## Architecture

```
+---------------------------------------------------------+
|                   Omarchy Wayland Bar                   |
|                      [ OmaBlock ]                       |
+---------------------------+-----------------------------+
                            | QML IPC / Click
                            v
+---------------------------------------------------------+
|              OmaBlock Control Center (QML)              |
|   - Hero Toggle (ON/OFF)      - Realtime Metrics        |
|   - Category Matrix           - Self-Diagnostic Test    |
|   - Whitelist/Blacklist Chips - Update / Flush          |
+---------------------------+-----------------------------+
                            | CLI / Stdio JSON
                            v
+---------------------------------------------------------+
|              omablock-engine (Rust Native)              |
|   - Pre-bundled ~80k categorized rules                  |
|   - Category filter & Whitelist arithmetic              |
|   - Live latency benchmarking (<0.1ms)                  |
|   - Background updater (curl + deduplication)           |
+---------------------------+-----------------------------+
                            | Polkit helper (/usr/bin)
                            v
+---------------------------------------------------------+
|        omablock-hosts-sync & /etc/hosts Sinkhole        |
|   - Atomic replacement via os.replace                   |
|   - DNS cache purge via resolvectl flush-caches         |
|   - 0.0.0.0 sinkhole for instantaneous connection drop  |
+---------------------------------------------------------+
```

---

## Requirements

- cargo and rustc (Rust toolchain, for building from source)
- systemd-resolved (resolvectl, for flushing local DNS cache)

---

## Installation and Setup

### Why Building from Source is Required
Under the Omarchy Linux Security Standards (AGENTS.md Rule 5.3), precompiled binaries are strictly forbidden from Git repositories to guarantee user system integrity. Therefore, the native engine must be compiled from source on your local machine after adding the plugin.

### Step 1: Add the Plugin to Omarchy
```bash
omarchy plugin add https://github.com/ozdil/omarchy-omablock.git
```

### Step 2: Build the Native Engine (User-Space)
Navigate to the plugin directory and run the user-space build script:
```bash
cd ~/.config/omarchy/plugins/ozdil.omablock
./build.sh
```
This builds `omablock-engine` from source and places user executables in `~/.local/bin`.

### Step 3: Install System Sinkhole Helper (Optional)
To enable system-wide `/etc/hosts` and Polkit integration without raw password prompts, install the package via Arch package manager:
```bash
cd ~/.config/omarchy/plugins/ozdil.omablock
makepkg -si
```

### Step 4: Add to Omarchy Shell Configuration (Optional)
If not automatically added, place `ozdil.omablock` into `bar.layout.right` in `~/.config/omarchy/shell.json`:
```json
{
  "id": "ozdil.omablock"
}
```

### Step 5: Restart Shell
```bash
omarchy-restart-shell
```

---

## Removal & Uninstallation

To cleanly remove OmaBlock:
```bash
cd ~/.config/omarchy/plugins/ozdil.omablock
./uninstall.sh
sudo pacman -R omarchy-omablock 2>/dev/null || true
omarchy plugin remove ozdil.omablock
```

---

## CLI Usage

OmaBlock provides standalone CLI commands:

```bash
# View full status in JSON
omablock --status

# Toggle protection
omablock --toggle
omablock --enable
omablock --disable

# Toggle individual categories
omablock --toggle-category ads
omablock --toggle-category telemetry
omablock --toggle-category malware
omablock --toggle-category social

# Manage Whitelist
omablock --whitelist-add adservice.google.com
omablock --whitelist-remove adservice.google.com

# Manage Blacklist
omablock --blacklist-add annoying-site.com
omablock --blacklist-remove annoying-site.com

# Run real-time resolution test
omablock --test

# Sync latest rules from cloud blocklists
omablock --update

# Flush system DNS resolver cache
omablock --flush
```

---

## Security and Architecture Standards

OmaBlock complies strictly with the Omarchy Linux Security Standards (AGENTS.md):
- Safe File Synchronization: Hosts file modifications are performed atomically via staging files, ensuring no partial writes or DNS downtime.
- Subprocess Isolation: Process executions run in isolated process groups (`cmd.process_group(0)`) with monotonic deadlines and 64 KiB buffer caps.
- Input Sanitization: Domain inputs are strictly validated against domain name standards to prevent configuration poisoning.
- Plain Text UI: All dynamic text rendered in QML components utilizes `textFormat: Text.PlainText` to prevent script and markup injection.

---

## Support & Sponsorship

If you find OmaBlock useful and want to support independent Linux security tools:

<a href="https://buymeacoffee.com/ozdil" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 50px !important;width: 180px !important;" ></a>

---

## License

MIT License. See [LICENSE](LICENSE) for details.
