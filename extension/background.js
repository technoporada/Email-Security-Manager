/* Background service worker — context menus + API calls */

const API_BASE = "http://localhost:8000";

// Context menus
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "check-phone",
    title: "📱 Check phone: %s",
    contexts: ["selection"]
  });

  chrome.contextMenus.create({
    id: "check-link",
    title: "🔗 Check link: %s",
    contexts: ["link", "selection"]
  });

  chrome.contextMenus.create({
    id: "copy-abuse",
    title: "📋 Copy abuse template",
    contexts: ["page"]
  });

  chrome.contextMenus.create({
    id: "separator1",
    type: "separator",
    contexts: ["selection"]
  });

  chrome.contextMenus.create({
    id: "open-portal",
    title: "🛡️ Open Security Portal",
    contexts: ["page"]
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  const text = info.selectionText || info.linkUrl || "";

  switch (info.menuItemId) {
    case "check-phone":
      checkPhone(text, tab);
      break;
    case "check-link":
      checkLink(info.linkUrl || text, tab);
      break;
    case "copy-abuse":
      copyAbuseTemplate(tab);
      break;
    case "open-portal":
      chrome.tabs.create({ url: API_BASE });
      break;
  }
});

// Check phone via API
async function checkPhone(phone, tab) {
  try {
    const resp = await fetch(`${API_BASE}/api/phone/check?phone=${encodeURIComponent(phone)}`);
    const data = await resp.json();
    showNotification(tab, `Phone ${phone}: ${data.risk} risk (${data.reports} reports)`);
    await copyToClipboard(phone);
  } catch (e) {
    showNotification(tab, `Phone ${phone}: API offline — copied to clipboard`);
    await copyToClipboard(phone);
  }
}

// Check link via API
async function checkLink(url, tab) {
  try {
    const resp = await fetch(`${API_BASE}/api/link/check?url=${encodeURIComponent(url)}`);
    const data = await resp.json();
    showNotification(tab, `Link: ${data.verdict} — ${data.risks.length} risks`);
  } catch (e) {
    // Fallback: open VirusTotal
    chrome.tabs.create({ url: `https://www.virustotal.com/gui/url/${encodeURIComponent(url)}` });
  }
}

// Copy abuse template
async function copyAbuseTemplate(tab) {
  try {
    const resp = await fetch(`${API_BASE}/api/abuse/templates`);
    const templates = await resp.json();
    const first = Object.values(templates)[0];
    if (first) {
      await copyToClipboard(first.subject + "\n\nSend to: " + first.contacts.join(", "));
      showNotification(tab, "Abuse template copied!");
    }
  } catch (e) {
    showNotification(tab, "API offline");
  }
}

// Copy to clipboard
async function copyToClipboard(text) {
  try {
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: ["CLIPBOARD"],
      justification: "Copy to clipboard"
    });
  } catch (e) {
    // offscreen may already exist
  }

  chrome.runtime.sendMessage({ type: "copy", text: text });
}

// Show notification via content script
function showNotification(tab, message) {
  if (tab && tab.id) {
    chrome.tabs.sendMessage(tab.id, {
      type: "notification",
      message: message
    }).catch(() => {});
  }
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "check-phone") {
    fetch(`${API_BASE}/api/phone/check?phone=${encodeURIComponent(msg.phone)}`)
      .then(r => r.json())
      .then(data => sendResponse(data))
      .catch(e => sendResponse({ error: e.message }));
    return true;
  }

  if (msg.type === "check-link") {
    fetch(`${API_BASE}/api/link/check?url=${encodeURIComponent(msg.url)}`)
      .then(r => r.json())
      .then(data => sendResponse(data))
      .catch(e => sendResponse({ error: e.message }));
    return true;
  }

  if (msg.type === "get-stats") {
    fetch(`${API_BASE}/api/stats`)
      .then(r => r.json())
      .then(data => sendResponse(data))
      .catch(() => sendResponse({ total_scans: 0, threats_found: 0, blacklisted: 0, abuse_reports: 0 }));
    return true;
  }

  if (msg.type === "copy") {
    copyToClipboard(msg.text);
    sendResponse({ ok: true });
    return true;
  }
});
