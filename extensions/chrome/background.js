// OmaBlock Chrome Bridge Service Worker (Manifest V3)
// Real-time badge status and declarative ruleset management for Omarchy

async function updateBadge(enabled) {
  try {
    if (enabled) {
      await chrome.action.setBadgeText({ text: "ON" });
      await chrome.action.setBadgeBackgroundColor({ color: "#22c55e" });
    } else {
      await chrome.action.setBadgeText({ text: "OFF" });
      await chrome.action.setBadgeBackgroundColor({ color: "#64748b" });
    }
  } catch (e) {
    // Context or action might be invalid in headless test
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  await updateBadge(true);
});

chrome.runtime.onStartup.addListener(async () => {
  await updateBadge(true);
});
