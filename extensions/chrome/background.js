// OmaBlock Chrome Bridge Service Worker (Manifest V3)
// Synchronizes with local OmaBlock Native Messaging Host & provides real-time shield state

const NATIVE_HOST = "com.omarchy.omablock";

let nativePort = null;

function connectNative() {
  try {
    nativePort = chrome.runtime.connectNative(NATIVE_HOST);
    nativePort.onMessage.addListener((msg) => {
      handleNativeMessage(msg);
    });
    nativePort.onDisconnect.addListener(() => {
      nativePort = null;
    });
  } catch (e) {
    nativePort = null;
  }
}

async function handleNativeMessage(msg) {
  if (!msg) return;
  if (msg.action === "update_status") {
    await chrome.storage.local.set({ omablock_status: msg.payload });
    updateBadge(msg.payload.enabled);
  }
}

async function updateBadge(enabled) {
  if (enabled) {
    await chrome.action.setBadgeText({ text: "ON" });
    await chrome.action.setBadgeBackgroundColor({ color: "#22c55e" });
  } else {
    await chrome.action.setBadgeText({ text: "OFF" });
    await chrome.action.setBadgeBackgroundColor({ color: "#64748b" });
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  await updateBadge(true);
  connectNative();
});

chrome.runtime.onStartup.addListener(() => {
  connectNative();
});
