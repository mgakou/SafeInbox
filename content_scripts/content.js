// content_scripts/content.js
// Analyse locale simplifiée pour popup – version sans bannière

(async () => {
  try {
    const { analyzeEmail, filtrerEmailAvantEnvoi } = await import(
      chrome.runtime.getURL("utils/anti_phish_scanner.js")
    );

    console.log("[SafeInbox] content script loaded");

    const SUBJECT_SELECTOR = 'h2.hP';
    const SENDER_SELECTOR  = '.gD';
    const BODY_SELECTOR    = '.a3s';
    const LINK_SELECTOR    = '.a3s a';
    const ATTACHMENT_SELECTOR = '[download_url]';

    function extractEmailData() {
      try {
        const subject = document.querySelector(SUBJECT_SELECTOR)?.innerText || "";
        const sender = document.querySelector(SENDER_SELECTOR)?.getAttribute("email") || "";
        const body = document.querySelector(BODY_SELECTOR)?.innerText || "";
        const links = Array.from(document.querySelectorAll(LINK_SELECTOR)).map(a => a.href);
        const attachments = Array.from(document.querySelectorAll(ATTACHMENT_SELECTOR))
          .map(el => el.getAttribute("download_url")?.split(":").pop());

        if (!subject && !body) return null;
        return { subject, sender, body, links, attachments };
      } catch (e) {
        console.warn("[SafeInbox] Erreur extraction email:", e);
        return null;
      }
    }

    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (msg.action === 'scanEmail') {
        const emailData = extractEmailData();
        if (!emailData) {
          sendResponse({ ok: false, error: "Impossible d'extraire l'email" });
          return true;
        }

        try {
          const score = analyzeEmail(emailData);
          sendResponse({ ok: true, result: score });
        } catch (e) {
          sendResponse({ ok: false, error: e.message });
        }
        return true;
      }

      if (msg.action === 'deepScanEmail') {
        const emailData = extractEmailData();
        if (!emailData) {
          sendResponse({ ok: false, error: "Impossible d'extraire l'email" });
          return true;
        }

        let filtered;
        try {
          filtered = filtrerEmailAvantEnvoi(emailData);
        } catch (e) {
          sendResponse({ ok: false, error: e.message });
          return true;
        }

        chrome.runtime.sendMessage(
          { action: 'deepScan', payload: filtered },
          (res) => {
            if (chrome.runtime.lastError) {
              sendResponse({ ok: false, error: chrome.runtime.lastError.message });
              return;
            }
            sendResponse(res);
          }
        );
        return true;
      }
    });

  } catch (err) {
    console.error("[SafeInbox] Erreur import anti_phish_scanner.js :", err);
  }
})();