// OmaBlock Chrome Bridge Service Worker (Manifest V3)
// Per-tab badge status and declarative ruleset management for Omarchy

importScripts('whitelist.js');

async function resyncAllowRules() {
  try {
    const store = await chrome.storage.local.get(['omablock_whitelist']);
    await omablockSyncAllowRules(store.omablock_whitelist || []);
  } catch (e) {
    // Rules stay as they were; the popup resyncs on the next toggle
  }
}

async function getWhitelist() {
  try {
    const store = await chrome.storage.local.get(['omablock_whitelist']);
    return store.omablock_whitelist || [];
  } catch (e) {
    return [];
  }
}

// "ON" while the shield filters this tab, "OFF" on a whitelisted site, empty on
// pages the extension does not touch (chrome://, file://, new tab).
async function updateTabBadge(tabId, url, whitelist) {
  let text = '';
  let color = '#22c55e';
  try {
    const parsed = new URL(url || '');
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      const host = parsed.hostname.toLowerCase();
      const off = whitelist.some(wl => omablockMatchesHost(host, wl));
      text = off ? 'OFF' : 'ON';
      color = off ? '#64748b' : '#22c55e';
    }
  } catch (e) {
    // Unparseable URL: leave the badge empty
  }
  try {
    await chrome.action.setBadgeText({ tabId, text });
    if (text) {
      await chrome.action.setBadgeBackgroundColor({ tabId, color });
    }
  } catch (e) {
    // Tab may have closed in the meantime
  }
}

async function updateAllBadges() {
  const whitelist = await getWhitelist();
  try {
    const tabs = await chrome.tabs.query({});
    await Promise.all(tabs.map(t => updateTabBadge(t.id, t.url, whitelist)));
  } catch (e) {
    // Ignore: badges refresh on the next tab event
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  // Restore allow rules for whitelists saved before this version (or after an update)
  await resyncAllowRules();
  await updateAllBadges();
});

chrome.runtime.onStartup.addListener(updateAllBadges);

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === 'loading') {
    await updateTabBadge(tabId, tab.url, await getWhitelist());
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.omablock_whitelist) {
    updateAllBadges();
  }
});
