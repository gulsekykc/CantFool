console.log("Popup.js loaded!");

const BACKEND_URL = "http://127.0.0.1:5000/predict_full";
const LINKCHECK_URL = "http://127.0.0.1:5000/check_link";

const analyzeBtn = document.getElementById("analyzeBtn");
const resultDiv = document.getElementById("result");
const loadingEl = document.getElementById("loading");
const confidenceFill = document.getElementById("confidenceFill");
const linksDiv = document.getElementById("links");

function setLoading(isLoading) {
  loadingEl.style.display = isLoading ? "block" : "none";
  analyzeBtn.disabled = isLoading;
}

function formatReasons(reasons) {
  if (!Array.isArray(reasons) || reasons.length === 0) return "";
  return ` [${reasons.join(", ")}]`;
}

async function checkLink(link) {
  try {
    const res = await fetch(LINKCHECK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: link })
    });
    return await res.json();
  } catch (e) {
    console.error("Link check error:", e);
    return { url: link, status: "error", reasons: ["network_error"] };
  }
}

function shortenLink(link, maxLen = 40) {
  try {
    const url = new URL(link);
    const host = url.hostname;
    const path = url.pathname === "/" ? "" : url.pathname;
    const display = host + path;
    if (display.length <= maxLen) return display;
    return display.slice(0, maxLen - 3) + "...";
  } catch (e) {
    if (!link) return "";
    if (link.length <= maxLen) return link;
    return link.slice(0, maxLen - 3) + "...";
  }
}

// Toggle section oluşturucu
function createToggleSection(title, links, className) {
  const container = document.createElement("div");
  const header = document.createElement("div");
  header.textContent = `${title} (${links.length})`;
  header.className = "toggle-header";

  const toggleBtn = document.createElement("button");
  toggleBtn.textContent = "Show/Hide";
  toggleBtn.className = "toggle-btn";
  header.appendChild(toggleBtn);

  const list = document.createElement("div");
  list.style.display = "none";

  links.forEach(linkText => {
    const div = document.createElement("div");
    div.textContent = linkText;
    div.className = className;
    list.appendChild(div);
  });

  toggleBtn.addEventListener("click", () => {
    list.style.display = list.style.display === "none" ? "block" : "none";
  });

  container.appendChild(header);
  container.appendChild(list);
  return container;
}

analyzeBtn.addEventListener("click", async () => {
  setLoading(true);
  linksDiv.innerHTML = "";

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) {
    resultDiv.textContent = "No active tab.";
    setLoading(false);
    return;
  }

  chrome.tabs.sendMessage(tab.id, { action: "analyzeEmail" }, async (response) => {
    if (!response || (!response.body && (!response.links || response.links.length === 0))) {
      resultDiv.textContent = "No email detected.";
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(BACKEND_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(response)
      });
      const data = await res.json();

      const confidencePct = Math.round((data.confidence || 0) * 100);

      // Güvenli sender fallback
      const senderText = response.sender && response.sender.trim() ? response.sender.trim() : "Unknown";

      // Body preview: ilk 5 kelime
      const body = response.body || "";
      const bodyPreview = body.split(/\s+/).filter(Boolean).slice(0, 5).join(" ");
      const previewText = bodyPreview + (body.length > bodyPreview.length ? "..." : "");

      // Gösterim
      resultDiv.textContent =
        `Sender: ${senderText}\n` +
        `Body preview: ${previewText}\n\n`+
        `Phishing: ${data.label}\n` +
        `Confidence: ${confidencePct}%`;
      // Confidence bar
      confidenceFill.style.width = `${confidencePct}%`;
      confidenceFill.className = data.label === "phishing" ? "confidence-fill suspicious" : "confidence-fill safe";

      // Link analizi
      const links = Array.isArray(response.links) ? response.links : [];
      if (links.length > 0) {
        linksDiv.innerHTML = "<strong>Links</strong><br>";

        const results = await Promise.all(links.map(link => checkLink(link)));

        const phishingLinks = [];
        const safeLinks = [];
        const unknownLinks = [];

        results.forEach((r, i) => {
          const status = r.status || "error";
          const reasons = formatReasons(r.reasons);

          if (status === "phishing") {
            phishingLinks.push(`${links[i]} → phishing${reasons}`);
          } else if (status === "legitimate") {
            const short = shortenLink(links[i], 50);
            safeLinks.push(`${short} → safe`);
          } else {
            const short = shortenLink(links[i], 50);
            unknownLinks.push(`${short} → unknown${reasons}`);
          }
        });

        // Toggle kullanımı
        if (phishingLinks.length > 5) {
          linksDiv.appendChild(createToggleSection("Phishing Links", phishingLinks, "link-suspicious"));
        } else {
          phishingLinks.forEach(l => {
            const div = document.createElement("div");
            div.textContent = l;
            div.className = "link-suspicious";
            linksDiv.appendChild(div);
          });
        }

        if (safeLinks.length > 5) {
          linksDiv.appendChild(createToggleSection("Safe Links", safeLinks, "link-safe"));
        } else {
          safeLinks.forEach(l => {
            const div = document.createElement("div");
            div.textContent = l;
            div.className = "link-safe";
            linksDiv.appendChild(div);
          });
        }

        if (unknownLinks.length > 0) {
          linksDiv.appendChild(createToggleSection("Unknown Links", unknownLinks, "link-unknown"));
        }
      }

    } catch (e) {
      console.error("Backend error:", e);
      resultDiv.textContent = "Backend unreachable.";
    } finally {
      setLoading(false);
    }
  });
});
