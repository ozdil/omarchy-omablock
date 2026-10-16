// OmaBlock Bridge Popup Controller
// Manages per-domain whitelist toggle directly within the browser

// Localized string from _locales (falls back to the key if a message is missing)
function t(key) {
  return chrome.i18n.getMessage(key) || key;
}

document.addEventListener('DOMContentLoaded', async () => {
  document.documentElement.lang = chrome.i18n.getUILanguage();
  for (const el of document.querySelectorAll('[data-i18n]')) {
    el.textContent = t(el.dataset.i18n);
  }

  const activeDomainEl = document.getElementById('activeDomain');
  const statusBadgeEl = document.getElementById('statusBadge');
  const toggleBtn = document.getElementById('toggleBtn');
  const versionBadgeEl = document.getElementById('versionBadge');
  if (versionBadgeEl) {
    versionBadgeEl.textContent = 'v' + chrome.runtime.getManifest().version;
  }

  // Query active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !tab.url.startsWith('http')) {
    activeDomainEl.textContent = t('unsupportedPage');
    statusBadgeEl.textContent = t('disabled');
    statusBadgeEl.style.color = '#94a3b8';
    toggleBtn.disabled = true;
    return;
  }

  let domain = '';
  try {
    const url = new URL(tab.url);
    domain = url.hostname.toLowerCase();
    activeDomainEl.textContent = domain;
  } catch (e) {
    activeDomainEl.textContent = t('invalidUrl');
    toggleBtn.disabled = true;
    return;
  }

  // Check store
  const store = await chrome.storage.local.get(['omablock_whitelist']);
  const whitelist = store.omablock_whitelist || [];
  // Same suffix match as content.js, so a parent-domain entry shows as whitelisted here too
  let isWhitelisted = whitelist.some(wl => omablockMatchesHost(domain, wl));

  function updateView() {
    if (isWhitelisted) {
      statusBadgeEl.textContent = t('whitelisted');
      statusBadgeEl.className = 'status-badge whitelisted';
      toggleBtn.textContent = t('enableHere');
    } else {
      statusBadgeEl.textContent = t('protected');
      statusBadgeEl.className = 'status-badge';
      toggleBtn.textContent = t('disableHere');
    }
  }

  updateView();

  toggleBtn.addEventListener('click', async () => {
    toggleBtn.disabled = true;
    try {
      const freshStore = await chrome.storage.local.get(['omablock_whitelist']);
      let list = freshStore.omablock_whitelist || [];

      if (isWhitelisted) {
        // Drop every entry covering this host (e.g. both www.example.com and example.com)
        list = list.filter(d => !omablockMatchesHost(domain, d));
        isWhitelisted = false;
      } else {
        if (!list.includes(domain)) {
          list.push(domain);
        }
        isWhitelisted = true;
      }

      await chrome.storage.local.set({ omablock_whitelist: list });
      // The service worker applies the allow rules from storage; wait for it before reloading
      const res = await chrome.runtime.sendMessage({ type: 'omablock-sync-allow-rules' });
      if (!res || !res.ok) {
        throw new Error('allow rules not updated');
      }
      updateView();

      // Reload tab to apply changes
      chrome.tabs.reload(tab.id);
    } catch (e) {
      statusBadgeEl.textContent = t('error');
    } finally {
      toggleBtn.disabled = false;
    }
  });
});
