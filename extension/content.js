// Robust extractor that handles dynamic Gmail DOM and iframes
function getSender() {
  const el =
    document.querySelector(".go") ||
    document.querySelector(".gD") ||
    document.querySelector(".afn");
  return el ? el.innerText.trim() : "Unknown";
}

function getBodyAndLinksFromMainDoc() {
  const bodyEl =
    document.querySelector(".a3s.aiL") ||
    document.querySelector(".a3s") ||
    document.querySelector(".adn.ads") ||
    document.querySelector(".ii.gt");
  const body = bodyEl ? bodyEl.innerText.trim() : "";

  const linkScope = bodyEl || document;
  const links = [...linkScope.querySelectorAll("a[href]")].map(a => a.href);

  return { body, links };
}

function getBodyAndLinksFromIframe() {
  const frames = [...document.querySelectorAll("iframe")];
  for (const iframe of frames) {
    try {
      const doc = iframe.contentDocument || iframe.contentWindow?.document;
      if (!doc) continue;
      const bodyEl =
        doc.querySelector(".a3s.aiL") ||
        doc.querySelector(".a3s") ||
        doc.body;
      const body = bodyEl ? bodyEl.innerText.trim() : "";
      const links = [...doc.querySelectorAll("a[href]")].map(a => a.href);
      if (body || links.length) return { body, links };
    } catch (e) {
      // cross-origin iframes will throw; ignore
    }
  }
  return { body: "", links: [] };
}

function extractEmailData() {
  const sender = getSender();

  let { body, links } = getBodyAndLinksFromMainDoc();
  if (!body && links.length === 0) {
    const fromFrame = getBodyAndLinksFromIframe();
    body = fromFrame.body;
    links = fromFrame.links;
  }

  return { sender, body, links };
}

// Wait until Gmail thread view renders using MutationObserver
let latestData = null;
const observer = new MutationObserver(() => {
  const data = extractEmailData();
  if (data.body || (data.links && data.links.length)) {
    latestData = data;
    console.log("Gmail content detected:", data);
  }
});
observer.observe(document.documentElement, { childList: true, subtree: true });

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  console.log("Message received in content.js:", msg);
  if (msg.action === "analyzeEmail") {
    const data = latestData || extractEmailData();
    console.log("Extracted data to send:", data);
    sendResponse(data);
    // No async work; no need to return true
  }
});
