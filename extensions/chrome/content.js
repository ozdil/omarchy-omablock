// OmaBlock DOM Sentinel Content Script
// Ensures zero-FOUC elimination of dynamically injected first-party ads with full whitelist bypass support

(async function() {
  'use strict';

  const hostname = window.location.hostname.toLowerCase();

  // 1. Built-in essential service protections
  // YouTube, Google Search, Wikipedia, and essential productivity tools must never have destructive DOM mutations applied
  const PROTECTED_DOMAINS = [
    'youtube.com',
    'www.youtube.com',
    'm.youtube.com',
    'google.com',
    'www.google.com',
    'github.com',
    'wikipedia.org'
  ];

  for (const domain of PROTECTED_DOMAINS) {
    if (hostname === domain || hostname.endsWith('.' + domain)) {
      return; // Completely bypass cosmetic content scripts on protected platforms
    }
  }

  // 2. Check dynamic whitelist from chrome.storage.local (synced from OmaBlock Engine)
  try {
    const store = await chrome.storage.local.get(['omablock_whitelist', 'omablock_disabled']);
    if (store && store.omablock_disabled) {
      return;
    }
    const whitelist = store && store.omablock_whitelist ? store.omablock_whitelist : [];
    for (const wl of whitelist) {
      const cleanWl = String(wl).toLowerCase().trim();
      if (cleanWl && (hostname === cleanWl || hostname.endsWith('.' + cleanWl))) {
        return; // Domain is whitelisted by user in OmaBlock
      }
    }
  } catch (e) {
    // Fail-open for safety
  }

  // 3. Precision DOM Purge for target first-party ad publishers (e.g. DonanımHaber)
  function purgeInlineAds() {
    if (!hostname.includes('donanimhaber.com')) {
      return;
    }
    const adAnchors = document.querySelectorAll('a[href*="ad.donanimhaber.com"], a[href*="adserve.donanimhaber.com"], div#rotator0, div#rotator1, div#rotator2');
    for (let i = 0; i < adAnchors.length; i++) {
      const el = adAnchors[i];
      if (el && el.parentNode) {
        el.style.setProperty('display', 'none', 'important');
        el.style.setProperty('visibility', 'hidden', 'important');
        el.style.setProperty('height', '0', 'important');
      }
    }
  }

  // Run on initial parse
  purgeInlineAds();

  // Low-overhead observer for single-page dynamic insertions
  if (document.body) {
    const observer = new MutationObserver(() => {
      purgeInlineAds();
    });
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      purgeInlineAds();
      if (document.body) {
        const observer = new MutationObserver(() => {
          purgeInlineAds();
        });
        observer.observe(document.body, { childList: true, subtree: true });
      }
    });
  }
})();
