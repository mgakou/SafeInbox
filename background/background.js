// background/background.js
// Gestion des actions de deep scan et récupération du dernier rapport

const API_ENDPOINT = "https://ton-backend-api/analyze";
const NOTIFICATION_ID = "deep-scan-result";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "deepScan") {
    // Lance l'analyse approfondie via l'API backend
    const emailData = msg.data;
    fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: emailData })
    })
      .then(res => res.json())
      .then(report => {
        // Ajoute un timestamp et stocke le rapport
        const fullReport = {
          score: report.score,
          summary: report.summary,
          timestamp: Date.now()
        };
        chrome.storage.local.set({ lastDeepScan: fullReport });

        // Affiche une notification utilisateur
        chrome.notifications.create(NOTIFICATION_ID, {
          type: "basic",
          iconUrl: chrome.runtime.getURL("icons/icon128.png"),
          title: "Analyse approfondie terminée",
          message: `Score: ${fullReport.score}/100\n${fullReport.summary}`
        });
      })
      .catch(err => {
        console.error("Deep scan API error:", err);
        chrome.notifications.create(NOTIFICATION_ID, {
          type: "basic",
          iconUrl: chrome.runtime.getURL("icons/icon128.png"),
          title: "Erreur analyse approfondie",
          message: "Impossible de contacter le service d'analyse."
        });
      });
    // Pas de sendResponse synchronisé
    return true;
  }

  if (msg.action === "getLastDeepScan") {
    // Récupère et renvoie le dernier rapport stocké
    chrome.storage.local.get("lastDeepScan", ({ lastDeepScan }) => {
      sendResponse({ report: lastDeepScan });
    });
    return true; // Garde le canal ouvert pour sendResponse
  }
});