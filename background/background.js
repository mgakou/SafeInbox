// background/background.js
// Deep Scan (V2) : reçoit la demande, appelle le backend, répond au content script,
// notifie l’utilisateur et mémorise le dernier rapport.

const API_ENDPOINT = "http://127.0.0.1:4000/api/analyze"; // backend FastAPI en dev
const NOTIFICATION_ID = "deep-scan-result";
const REQ_TIMEOUT_MS = 15000; // 15s
const DEV_TOKEN = "change-me-for-dev"; // doit correspondre à DEV_SHARED_TOKEN dans backend/.env

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // --- Deep Scan ------------------------------------------------------------
  if (msg?.action === "deepScan") {
    // compat: content.js peut envoyer {data:...} ou {payload:...}
    const emailData = msg.payload ?? msg.data ?? null;
    // Nouveau: si le caller envoie déjà { provider, prompt, url, minimal }, on le passe tel quel.
    const payload = (msg.payload ?? msg.data) || null;
    if (!payload && !emailData) {
      sendResponse({ ok: false, error: "No payload provided" });
      return; // pas besoin d’async ici
    }

    // timeout via AbortController (évite worker qui reste suspendu)
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort("timeout"), REQ_TIMEOUT_MS);

    (async () => {
      try {
        const res = await fetch(API_ENDPOINT, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Dev-Token": DEV_TOKEN,
          },
          // Priorité au nouveau format; fallback legacy { email }
          body: JSON.stringify(payload ?? { email: emailData }),
          signal: ctrl.signal,
        });

        const report = await res.json();

        // Normalisation du rapport pour l'UI
        let score = 0;
        let summary = "Analyse terminée";

        if (typeof report.score !== "undefined" || typeof report.summary !== "undefined") {
          // Compat : ancien backend qui renvoie directement {score, summary}
          score = Number(report.score) || 0;
          summary = String(report.summary || summary);
        } else if (report && typeof report === "object") {
          const provider = report.provider || (report.data && report.data.provider);
          const data = report.data ?? report;

          if (provider === "virustotal") {
            // Heuristique simple depuis VT: compte les détections malveillantes
            try {
              const stats = data?.data?.attributes?.stats || data?.data?.attributes?.last_analysis_stats;
              const malicious = Number(stats?.malicious || 0);
              const suspicious = Number(stats?.suspicious || 0);
              const harmless = Number(stats?.harmless || 0);
              const undetected = Number(stats?.undetected || 0);
              const total = malicious + suspicious + harmless + undetected;
              // Score sur 100 : proportion de mal/susp parmi total connu
              score = total > 0 ? Math.min(100, Math.round(((malicious + suspicious) / total) * 100)) : 0;
              summary = `VirusTotal: ${malicious} malveillants, ${suspicious} suspects / ${total} scanners`;
            } catch (_) {
              summary = "VirusTotal: analyse reçue";
            }
          } else if (provider === "openai") {
            // Essaie d'extraire le texte du premier choix
            try {
              const text = data?.choices?.[0]?.message?.content || data?.choices?.[0]?.text || "Réponse OpenAI reçue";
              summary = (text || "").slice(0, 180);
              score = 0; // pas de score natif — à calculer côté serveur si besoin
            } catch (_) {
              summary = "OpenAI: réponse reçue";
            }
          }
        }

        const fullReport = {
          score,
          summary,
          raw: report,
          timestamp: Date.now(),
        };

        // mémoriser
        await chrome.storage.local.set({ lastDeepScan: fullReport });

        // notifier l’utilisateur (optionnel)
        try {
          await chrome.notifications.create(NOTIFICATION_ID, {
            type: "basic",
            iconUrl: chrome.runtime.getURL("icons/icon128.png"),
            title: "Analyse approfondie terminée",
            message: `Score: ${fullReport.score}/100\n${fullReport.summary}`,
            priority: 0,
          });
        } catch (_) { /* permissions manquantes ou icône absente → on ignore */ }

        // répondre au content script (pour l’iframe)
        sendResponse({ ok: true, data: fullReport });
      } catch (err) {
        const msg = (err && err.name === "AbortError") ? "Timeout" : String(err);
        console.error("[DeepScan] backend error:", msg);

        try {
          await chrome.notifications.create(NOTIFICATION_ID, {
            type: "basic",
            iconUrl: chrome.runtime.getURL("icons/icon128.png"),
            title: "Erreur analyse approfondie",
            message: "Impossible de contacter le backend d'analyse (verifie que le serveur FastAPI tourne).",
            priority: 0,
          });
        } catch (_) {}

        sendResponse({ ok: false, error: msg });
      } finally {
        clearTimeout(t);
      }
    })();

    return true; // ← garde le canal ouvert pour la réponse async
  }

  // --- Dernier rapport ------------------------------------------------------
  if (msg?.action === "getLastDeepScan") {
    chrome.storage.local.get("lastDeepScan", ({ lastDeepScan }) => {
      sendResponse({ ok: true, report: lastDeepScan ?? null });
    });
    return true;
  }
});