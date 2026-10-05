// OmaBlock Bridge Popup Controller
// Manages per-domain whitelist toggle directly within the browser

document.addEventListener('DOMContentLoaded', async () => {
  const activeDomainEl = document.getElementById('activeDomain');
  const statusBadgeEl = document.getElementById('statusBadge');
  const toggleBtn = document.getElementById('toggleBtn');

  // Query active tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url || !tab.url.startsWith('http')) {
    activeDomainEl.textContent = 'Desteklenmeyen Sayfa';
    statusBadgeEl.textContent = 'Devre Dışı';
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
    activeDomainEl.textContent = 'Gecersiz URL';
    toggleBtn.disabled = true;
    return;
  }

  // Check store
  const store = await chrome.storage.local.get(['omablock_whitelist']);
  const whitelist = store.omablock_whitelist || [];
  let isWhitelisted = whitelist.includes(domain);

  function updateView() {
    if (isWhitelisted) {
      statusBadgeEl.textContent = 'İzinli (Whitelist)';
      statusBadgeEl.className = 'status-badge whitelisted';
      toggleBtn.textContent = 'Bu Sitede Kalkanı Aç';
    } else {
      statusBadgeEl.textContent = 'Korumada';
      statusBadgeEl.className = 'status-badge';
      toggleBtn.textContent = 'Bu Sitede Kalkanı Kapat';
    }
  }

  updateView();

  toggleBtn.addEventListener('click', async () => {
    const freshStore = await chrome.storage.local.get(['omablock_whitelist']);
    let list = freshStore.omablock_whitelist || [];

    if (isWhitelisted) {
      list = list.filter(d => d !== domain);
      isWhitelisted = false;
    } else {
      if (!list.includes(domain)) {
        list.push(domain);
      }
      isWhitelisted = true;
    }

    await chrome.storage.local.set({ omablock_whitelist: list });
    updateView();

    // Reload tab to apply changes
    chrome.tabs.reload(tab.id);
  });
});
