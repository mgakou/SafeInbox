// background/background.js
// === Gestion des actions de Deep Scan et des expéditeurs ignorés ===

const API_ENDPOINT = "https://ton-backend-api/analyze";
const NOTIFICATION_ID = "deep-scan-result";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  /* ===========================
   * 1️⃣ Ignorer un expéditeur
   * =========================== */
  if (msg.action === "ignoreSender" && msg.sender) {
    const ignored = msg.sender.toLowerCase();

    chrome.storage.sync.get({ ignoredSenders: [] }, ({ ignoredSenders }) => {
      const updated = Array.from(new Set([...ignoredSenders, ignored]));
      chrome.storage.sync.set({ ignoredSenders: updated }, () => {
        console.log("[SafeInbox BG] Added to ignoredSenders:", ignored);
      });
    });

    // On ne bloque pas les autres messages, donc pas de return ici
  }

  /* ===========================
   * 2️⃣ Lancer un Deep Scan backend
   * =========================== */
  if (msg.action === "deepScan") {
    const emailData = msg.data;

    fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: emailData })
    })
      .then(res => res.json())
      .then(report => {
        const fullReport = {
          score: report.score,
          summary: report.summary,
          timestamp: Date.now()
        };

        // Stocker le dernier rapport localement
        chrome.storage.local.set({ lastDeepScan: fullReport });

        // Notifier l’utilisateur
        chrome.notifications.create(NOTIFICATION_ID, {
          type: "basic",
          iconUrl: chrome.runtime.getURL("icons/icon128.png"),
          title: "Analyse approfondie terminée",
          message: `Score: ${fullReport.score}/100\n${fullReport.summary}`
        });
      })
      .catch(err => {
        console.error("[SafeInbox] Deep scan API error:", err);
        chrome.notifications.create(NOTIFICATION_ID, {
          type: "basic",
          iconUrl: chrome.runtime.getURL("icons/icon128.png"),
          title: "Erreur analyse approfondie",
          message: "Impossible de contacter le service d'analyse."
        });
      });

    return true; // garde le canal ouvert
  }

  /* ===========================
   * 3️⃣ Récupérer le dernier rapport Deep Scan
   * =========================== */
  if (msg.action === "getLastDeepScan") {
    chrome.storage.local.get("lastDeepScan", ({ lastDeepScan }) => {
      sendResponse({ report: lastDeepScan });
    });
    return true;
  }
});