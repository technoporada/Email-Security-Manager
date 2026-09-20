/* Content script — shows toast notifications on pages */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "notification") {
    showToast(msg.message);
  }
});

function showToast(message) {
  const existing = document.getElementById("esm-toast");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.id = "esm-toast";
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    background: #1a1a2e;
    color: #ff4757;
    padding: 12px 24px;
    border-radius: 12px;
    border: 1px solid #ff4757;
    font-family: 'Courier New', monospace;
    font-size: 14px;
    font-weight: bold;
    z-index: 999999;
    box-shadow: 0 4px 20px rgba(255, 71, 87, 0.4);
    animation: esm-fade-in 0.3s ease;
    max-width: 90vw;
    text-align: center;
  `;

  const style = document.createElement("style");
  style.textContent = `
    @keyframes esm-fade-in { from { opacity: 0; transform: translateX(-50%) translateY(10px); } to { opacity: 1; transform: translateX(-50%) translateY(0); } }
    @keyframes esm-fade-out { from { opacity: 1; } to { opacity: 0; } }
  `;
  document.head.appendChild(style);
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = "esm-fade-out 0.3s ease forwards";
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}
