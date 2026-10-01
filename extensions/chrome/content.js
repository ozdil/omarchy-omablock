// OmaBlock DOM Sentinel Content Script
// Ensures zero-FOUC elimination of dynamically injected first-party ad scripts and frames

(function() {
  'use strict';

  function purgeInlineAds() {
    // Purge known ad rotator scripts or custom frames
    const adAnchors = document.querySelectorAll('a[href*="ad.donanimhaber.com"], a[href*="adserve.donanimhaber.com"], [id^="rotator"]');
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
