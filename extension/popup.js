/* Popup.js — all popup logic */

const API_BASE = "http://localhost:8000";

// Load stats on open
document.addEventListener("DOMContentLoaded", loadStats);

async function loadStats() {
  try {
    const resp = await fetch(`${API_BASE}/api/stats`);
    const data = await resp.json();
    document.getElementById("statScans").textContent = data.total_scans;
    document.getElementById("statThreats").textContent = data.threats_found;
    document.getElementById("statBlocked").textContent = data.blacklisted;
  } catch (e) {
    document.getElementById("statScans").textContent = "0";
    document.getElementById("statThreats").textContent = "0";
    document.getElementById("statBlocked").textContent = "0";
  }
}

// Phone check
async function checkPhone() {
  const phone = document.getElementById("phoneInput").value.trim();
  if (!phone) return;

  const el = document.getElementById("phoneResult");
  el.className = "result show";
  el.innerHTML = "⏳ Checking...";

  try {
    const resp = await fetch(`${API_BASE}/api/phone/check?phone=${encodeURIComponent(phone)}`);
    const data = await resp.json();
    const riskCls = data.risk === "high" ? "badge-danger" : data.risk === "medium" ? "badge-warning" : data.risk === "low" ? "badge-safe" : "badge-unknown";

    el.innerHTML = `
      <div><strong>${data.phone}</strong></div>
      <div style="margin:4px 0">
        <span class="badge ${riskCls}">${data.risk.toUpperCase()}</span>
        <span style="color:#888;font-size:0.8em">${data.reports} reports</span>
      </div>
      ${data.categories.length > 0 ? `<div style="color:#888;font-size:0.8em">${data.categories.join(", ")}</div>` : ""}
      <div style="margin-top:6px">
        <button class="secondary" onclick="copyText('${phone}')" style="font-size:0.75em">📋 Copy number</button>
        <button class="secondary" onclick="openDB('tellows','${phone}')" style="font-size:0.75em">🔍 Tellows</button>
      </div>
    `;

    // Auto-copy high risk numbers
    if (data.risk === "high") {
      await navigator.clipboard.writeText(phone).catch(() => {});
    }
  } catch (e) {
    el.innerHTML = `<span style="color:#ff4757">API offline — copy number and check manually</span>
      <div style="margin-top:4px"><button class="secondary" onclick="copyText('${phone}')" style="font-size:0.75em">📋 Copy</button></div>`;
  }
}

// Link check
async function checkLink() {
  const url = document.getElementById("linkInput").value.trim();
  if (!url) return;

  const el = document.getElementById("linkResult");
  el.className = "result show";
  el.innerHTML = "⏳ Checking...";

  try {
    const resp = await fetch(`${API_BASE}/api/link/check?url=${encodeURIComponent(url)}`);
    const data = await resp.json();
    const verdictCls = data.verdict === "safe" ? "badge-safe" : data.verdict === "malicious" ? "badge-danger" : "badge-warning";

    el.innerHTML = `
      <div><span class="badge ${verdictCls}" style="font-size:0.9em;padding:3px 10px">${data.verdict.toUpperCase()}</span></div>
      ${data.risks.length > 0 ? `<div style="margin-top:6px">${data.risks.map(r => `<div style="color:#ff4757;font-size:0.8em">⚠ ${r}</div>`).join("")}</div>` : `<div style="color:#2ed573;font-size:0.8em;margin-top:4px">✅ No threats detected</div>`}
    `;
  } catch (e) {
    el.innerHTML = `<span style="color:#ff4757">API offline</span>
      <div style="margin-top:4px"><button class="secondary" onclick="window.open('https://www.virustotal.com/gui/url/${encodeURIComponent(url)}')" style="font-size:0.75em">Open VirusTotal</button></div>`;
  }
}

// Copy abuse template
async function copyAbuseTemplate(type) {
  const el = document.getElementById("abuseResult");
  el.className = "result show";
  el.innerHTML = "⏳ Generating...";

  try {
    const resp = await fetch(`${API_BASE}/api/abuse/generate?report_type=${type}`, { method: "POST" });
    const data = await resp.json();
    if (data.body) {
      await navigator.clipboard.writeText(data.body).catch(() => {});
      el.innerHTML = `<div style="color:#2ed573">✅ ${type.toUpperCase()} template copied!</div><div style="color:#888;font-size:0.75em;margin-top:4px">Send to: ${data.contacts.join(", ")}</div>`;
    }
  } catch (e) {
    el.innerHTML = `<span style="color:#ff4757">API offline</span>`;
  }
}

// Open phone databases
function openDB(db, phone = "") {
  const urls = {
    tellows: phone ? `https://www.tellows.pl/num/${phone.replace(/[\s\-\(\)\+]/g, "")}` : "https://www.tellows.pl/",
    nienadzwon: phone ? `https://nienadzwon.pl/numer/${phone.replace(/[\s\-\(\)\+]/g, "")}` : "https://nienadzwon.pl/",
    jakitonumer: phone ? `https://www.jakitonumer.pl/numer/${phone.replace(/[\s\-\(\)\+]/g, "")}` : "https://www.jakitonumer.pl/",
  };
  window.open(urls[db], "_blank");
}

// Open external tools
function openVT() {
  const url = document.getElementById("linkInput").value.trim();
  window.open(url ? `https://www.virustotal.com/gui/url/${encodeURIComponent(url)}` : "https://www.virustotal.com", "_blank");
}

function openURLScan() {
  const url = document.getElementById("linkInput").value.trim();
  window.open(url ? `https://urlscan.io/search/#${encodeURIComponent(url)}` : "https://urlscan.io", "_blank");
}

function openAbuseIPDB() {
  const url = document.getElementById("linkInput").value.trim();
  window.open("https://www.abuseipdb.com", "_blank");
}

// Copy text
async function copyText(text) {
  await navigator.clipboard.writeText(text).catch(() => {});
}
