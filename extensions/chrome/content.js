// OmaBlock DOM Sentinel Content Script
// Ensures zero-FOUC elimination of verified ads with dynamic whitelist bypass and zero UI breakage

(async function() {
  'use strict';

  const hostname = window.location.hostname.toLowerCase();
  const isSite = (site) => hostname === site || hostname.endsWith('.' + site);

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

  // 2. Inject Safe Dynamic CSS Rules first, before the async storage read, so ads
  //    never flash in; it is removed again below if the site is whitelisted.
  //    (Scoped strictly to confirmed advertising elements)
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

  // 3. Dynamic Whitelist Check (popup toggle; same matcher as the popup via whitelist.js)
  try {
    const store = await chrome.storage.local.get(['omablock_whitelist']);
    const whitelist = (store && store.omablock_whitelist) ? store.omablock_whitelist : [];
    if (whitelist.some(wl => omablockMatchesHost(hostname, wl))) {
      styleEl.remove();
      return; // Current domain is whitelisted
    }
  } catch (e) {
    // Fail-safe: keep filtering
  }

  // 4. Site-Specific First-Party Element Purge (e.g. DonanımHaber)
  function purgeFirstPartyAds() {
    if (isSite('donanimhaber.com')) {
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
    } else if (isSite('haberler.com')) {
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

  // First-party purging only applies to a couple of sites; skip the observer elsewhere.
  if (!isSite('donanimhaber.com') && !isSite('haberler.com')) {
    return;
  }

  // Low-overhead mutation observer for single-page dynamic insertions,
  // coalesced to at most one purge per animation frame.
  let purgeScheduled = false;
  const schedulePurge = () => {
    if (purgeScheduled) return;
    purgeScheduled = true;
    requestAnimationFrame(() => {
      purgeScheduled = false;
      purgeFirstPartyAds();
    });
  };
  const startObserver = () => {
    if (document.body) {
      new MutationObserver(schedulePurge).observe(document.body, { childList: true, subtree: true });
    }
  };
  if (document.body) {
    startObserver();
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      purgeFirstPartyAds();
      startObserver();
    });
  }
})();
