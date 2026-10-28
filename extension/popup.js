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

    const phoneLabel = document.createElement("div");
    const phoneValue = document.createElement("strong");
    phoneValue.textContent = data.phone;
    phoneLabel.append(phoneValue);
    const riskDetails = document.createElement("div");
    riskDetails.style.margin = "4px 0";
    const riskBadge = document.createElement("span");
    riskBadge.className = `badge ${riskCls}`;
    riskBadge.textContent = data.risk.toUpperCase();
    const reportCount = document.createElement("span");
    reportCount.style.color = "#888";
    reportCount.style.fontSize = "0.8em";
    reportCount.textContent = `${data.reports} reports`;
    riskDetails.append(riskBadge, reportCount);
    const resultElements = [phoneLabel, riskDetails];
    if (data.categories.length > 0) {
      const categories = document.createElement("div");
      categories.style.color = "#888";
      categories.style.fontSize = "0.8em";
      categories.textContent = data.categories.join(", ");
      resultElements.push(categories);
    }
    const buttonContainer = document.createElement("div");
    buttonContainer.style.marginTop = "6px";
    const copyButton = document.createElement("button");
    copyButton.className = "secondary";
    copyButton.style.fontSize = "0.75em";
    copyButton.textContent = "📋 Copy number";
    copyButton.addEventListener("click", () => copyText(phone));
    buttonContainer.append(copyButton);
    resultElements.push(buttonContainer);
    el.replaceChildren(...resultElements);

    // Auto-copy high risk numbers
    if (data.risk === "high") {
      await navigator.clipboard.writeText(phone).catch(() => {});
    }
  } catch (e) {
    const message = document.createElement("span");
    message.style.color = "#ff4757";
    message.textContent = "API offline — uruchom backend i spróbuj ponownie";
    const buttonContainer = document.createElement("div");
    buttonContainer.style.marginTop = "4px";
    const copyButton = document.createElement("button");
    copyButton.className = "secondary";
    copyButton.style.fontSize = "0.75em";
    copyButton.textContent = "📋 Copy";
    copyButton.addEventListener("click", () => copyText(phone));
    buttonContainer.append(copyButton);
    el.replaceChildren(message, buttonContainer);
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
    el.innerHTML = `<span style="color:#ff4757">API offline — uruchom backend i spróbuj ponownie</span>`;
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

// Copy text
async function copyText(text) {
  await navigator.clipboard.writeText(text).catch(() => {});
}
