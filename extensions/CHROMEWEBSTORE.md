# OmaBlock Shield Bridge — Chrome Web Store Listing & Metadata

## 1. Extension Information
- **Title / Name**: OmaBlock Shield Bridge
- **Short Description**: High-performance ad, tracker and cosmetic element shield bridge for Omarchy Linux.
- **Detailed Description**:
OmaBlock Shield Bridge provides seamless browser-level ad and tracker filtering, working in concert with the Omarchy OmaBlock ecosystem.

Key Features:
- Zero-Latency Ad Blocking: Blocks unwanted network requests before they reach your browser using declarative filtering.
- Smart Cosmetic Filtering: Cleans up empty ad containers, sticky banners, and distracting elements on popular websites.
- First-Party Pop-up Shield: Prevents unwanted redirects and intrusive promotional overlays.
- Privacy First: Operates entirely locally. No user telemetry, browsing history, or personal data is collected or transmitted.

- **Category**: Productivity / Accessibility
- **Language**: Türkçe (Primary), English (Secondary)

---

## 2. Permissions Justifications (Store Review Team)

| Permission | Reason for Review Team |
| :--- | :--- |
| `declarativeNetRequest` | Required to block intrusive ad and tracker network requests directly in the browser network engine without reading user traffic. |
| `storage` | Used locally on the device to cache user preferences and active shield toggle states. No external data transmission. |
| `nativeMessaging` | Enables local communication with the host OmaBlock daemon on Omarchy Linux to synchronize protection status. |
| `<all_urls>` (Host Permission) | Essential to apply declarative network rules and cosmetic CSS filters across visited web pages to hide inline ad containers. |

---

## 3. Privacy & Data Use Disclosures
- **Single Purpose**: Ad blocking, tracker prevention and cosmetic layout cleanup.
- **Data Collection**: No personal data, cookies, authentication info, or browsing history is collected.
- **Third-Party Data Sharing**: None.
- **Website/Support**: https://github.com/ozdil/omarchy-omablock

---

## 4. Package File
- **Ready Upload File**: `/home/ozdil/Projects/omarchy/omarchy-omablock/extensions/omablock-chrome-bridge-v1.0.0.zip`
