# OmaBlock (ozdil.omablock)

> **Machine-Age Zero-Latency AdBlocker & Privacy Shield for Omarchy Linux**

OmaBlock is an intelligent, high-performance, kernel-level ad, tracker, and malware blocking shell plugin engineered natively for Omarchy Linux.

---

## Key Highlights

- **Zero Latency (< 0.1ms)**: Leverages atomic, kernel-level DNS sinkhole routing (`0.0.0.0`) without middleman proxy overhead or battery drain.
- **79,500+ Curated Rules**: Pre-bundled offline database + one-click online synchronization with StevenBlack Unified and EasyPrivacy upstream lists.
- **Fine-Grained Categories**:
  - `Ads & Commercial Banners`: DoubleClick, PageAd, Criteo, Taboola, Outbrain, popups, video ads.
  - `Telemetry & Surveillance`: Microsoft, Google Analytics, Firebase, Crashlytics, Branch.io, mobile trackers.
  - `Malware & Phishing`: Known command-and-control servers, cryptominers, phishing traps.
  - `Social Network Trackers`: Facebook Pixel, TikTok tracking beacons, Twitter tags.
- **Live Shield Verification**: In-panel live resolution diagnostics to verify protection in real-time.
- **Custom Whitelist & Blacklist**: Instantly allow or block individual domains with zero DNS downtime.
- **Pure Monochrome Design**: Compliant with Omarchy UI guidelines (clean typography, Nerd Font glyphs, zero colored emojis, full English UI).
- **Security First**: Adheres strictly to the Omarchy Security Guide with safe atomic file replacement, strict regex sanitization, and isolated privilege boundaries.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Omarchy Wayland Bar                  │
│                     [  OmaBlock ]                      │
└───────────────────────────┬─────────────────────────────┘
                            │ QML IPC / Click
                            ▼
┌─────────────────────────────────────────────────────────┐
│               OmaBlock Control Center (QML)             │
│   • Hero Toggle (ON/OFF)       • Realtime Metrics       │
│   • Category Matrix            • Self-Diagnostic Test   │
│   • Whitelist/Blacklist Chips  • Update / Flush         │
└───────────────────────────┬─────────────────────────────┘
                            │ CLI / Stdio JSON
                            ▼
┌─────────────────────────────────────────────────────────┐
│               omablock-engine (Rust Native)             │
│   • Pre-bundled ~80k categorized rules                  │
│   • Category filter & Whitelist arithmetic              │
│   • Live latency benchmarking (<0.1ms)                  │
│   • Background updater (curl + deduplication)           │
└───────────────────────────┬─────────────────────────────┘
                            │ Sudo helper (NOPASSWD)
                            ▼
┌─────────────────────────────────────────────────────────┐
│         omablock-hosts-sync & /etc/hosts Sinkhole       │
│   • Atomic replacement via os.replace                   │
│   • DNS cache purge via `resolvectl flush-caches`       │
│   • 0.0.0.0 sinkhole for instantaneous connection drop  │
└─────────────────────────────────────────────────────────┘
```

---

## CLI Usage

OmaBlock provides a standalone CLI binary `omablock` (and `omablock-engine`):

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

## License

MIT License © 2026 Ozan Özdil (ozdil).
