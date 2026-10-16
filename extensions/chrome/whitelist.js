// OmaBlock Bridge shared whitelist helpers (used by popup.js and background.js)
// Matching mirrors content.js: an entry covers the domain itself and all its subdomains.

const OMABLOCK_ALLOW_RULE_BASE_ID = 10000;

function omablockNormalize(entry) {
  return String(entry || '').toLowerCase().trim().replace(/\.+$/, '');
}

function omablockMatchesHost(hostname, entry) {
  const wl = omablockNormalize(entry);
  return !!wl && (hostname === wl || hostname.endsWith('.' + wl));
}

// Mirrors the whitelist into dynamic DNR allow rules so whitelisting a site also
// lifts the network-level blocks from rules.json, not just the cosmetic CSS.
async function omablockSyncAllowRules(whitelist) {
  const domains = [...new Set((whitelist || []).map(omablockNormalize).filter(Boolean))];
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing
    .map(r => r.id)
    .filter(id => id >= OMABLOCK_ALLOW_RULE_BASE_ID);
  const addRules = domains.map((domain, i) => ({
    id: OMABLOCK_ALLOW_RULE_BASE_ID + i,
    priority: 100,
    action: { type: 'allowAllRequests' },
    condition: { requestDomains: [domain], resourceTypes: ['main_frame', 'sub_frame'] }
  }));
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
}
