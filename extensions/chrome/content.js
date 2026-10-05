// OmaBlock DOM Sentinel Content Script
// Ensures zero-FOUC elimination of verified ads with dynamic whitelist bypass and zero UI breakage

(async function() {
  'use strict';

  const hostname = window.location.hostname.toLowerCase();

  // 1. Built-in essential service protections: Never touch critical productivity & video platforms
  const PROTECTED_DOMAINS = [
    'youtube.com',
    'www.youtube.com',
    'm.youtube.com',
    'youtu.be',
    'google.com',
    'www.google.com',
    'github.com',
    'wikipedia.org'
  ];

  for (const domain of PROTECTED_DOMAINS) {
    if (hostname === domain || hostname.endsWith('.' + domain)) {
      return; // Absolute zero-touch on protected platforms
    }
  }

  // 2. Dynamic Whitelist Check (Extension Storage synced or user toggle)
  try {
    const store = await chrome.storage.local.get(['omablock_disabled', 'omablock_whitelist']);
    if (store && store.omablock_disabled) {
      return; // Global extension pause
    }
    const whitelist = (store && store.omablock_whitelist) ? store.omablock_whitelist : [];
    for (const wl of whitelist) {
      const cleanWl = String(wl).toLowerCase().trim();
      if (cleanWl && (hostname === cleanWl || hostname.endsWith('.' + cleanWl))) {
        return; // Current domain is whitelisted
      }
    }
  } catch (e) {
    // Fail-safe: continue safely
  }

  // 3. Inject Safe Dynamic CSS Rules (Scoped strictly to confirmed advertising elements)
  const SAFE_CSS = `
    div[id*="google_ads"],
    div[id^="div-gpt-ad"],
    div[class*="dfp-ad"],
    div[class*="adsbygoogle"],
    ins.adsbygoogle,
    iframe[id*="google_ads_iframe"],
    .advertisement,
    .ad-banner,
    .sponsor-content,
    .outbrain,
    .taboola,
    .criteo-ad,
    .yandex-ad,
    [data-ad-unit],
    [data-ad-client],
    .popup-ad,
    .ad-overlay,
    .modal-advertisement,
    .floating-banner,
    #interstitial-ad,
    div[id*="interstitial-ad"],
    div[class*="interstitial-ad"] {
      display: none !important;
      visibility: hidden !important;
      height: 0 !important;
      pointer-events: none !important;
    }
  `;

  const styleEl = document.createElement('style');
  styleEl.id = 'omablock-dynamic-cosmetic';
  styleEl.textContent = SAFE_CSS;
  (document.head || document.documentElement).appendChild(styleEl);

  // 4. Site-Specific First-Party Element Purge (e.g. DonanımHaber)
  function purgeFirstPartyAds() {
    if (hostname.includes('donanimhaber.com')) {
      const targets = document.querySelectorAll(
        'a[href*="ad.donanimhaber.com"], a[href*="adserve.donanimhaber.com"], img[src*="adserve.donanimhaber.com"], div#rotator0, div#rotator1, div#rotator2, div#rotator3, div.reklam-alani, div[id^="dha-counter"]'
      );
      for (let i = 0; i < targets.length; i++) {
        const el = targets[i];
        if (el && el.parentNode) {
          el.style.setProperty('display', 'none', 'important');
          el.style.setProperty('visibility', 'hidden', 'important');
          el.style.setProperty('height', '0', 'important');
          el.style.setProperty('pointer-events', 'none', 'important');
        }
      }
    } else if (hostname.includes('haberler.com')) {
      const targets = document.querySelectorAll('#sticky-ad-container, .ana_masthead_1056x250');
      for (let i = 0; i < targets.length; i++) {
        const el = targets[i];
        if (el && el.parentNode) {
          el.style.setProperty('display', 'none', 'important');
          el.style.setProperty('visibility', 'hidden', 'important');
          el.style.setProperty('height', '0', 'important');
        }
      }
    }
  }

  // Initial purge
  purgeFirstPartyAds();

  // Low-overhead mutation observer for single-page dynamic insertions
  if (document.body) {
    const observer = new MutationObserver(() => {
      purgeFirstPartyAds();
    });
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      purgeFirstPartyAds();
      if (document.body) {
        const observer = new MutationObserver(() => {
          purgeFirstPartyAds();
        });
        observer.observe(document.body, { childList: true, subtree: true });
      }
    });
  }
})();
