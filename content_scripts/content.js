// content_scripts/content.js
// Analyse locale + bannière flottante avec auto-injection & resize iFrame

import(chrome.runtime.getURL("utils/local_scanner.js"))
  .then(({ analyzeEmail }) => {
    console.log("[AntiPhish] content script loaded");

    // === Constantes DOM / Config ===
    const GMAIL_SELECTOR = 'div[role="main"]';
    const SUBJECT_SELECTOR = 'h2.hP';
    const SENDER_SELECTOR  = '.gD';
    const BODY_SELECTOR    = '.a3s';
    const LINK_SELECTOR    = '.a3s a';
    const ATTACHMENT_SELECTOR = '[download_url]';
    const BANNER_ID = '#anti-phish-banner';
    const DEFAULT_THRESHOLD = 40;

    // === État ===
    let threshold = DEFAULT_THRESHOLD;
    let lastEmailData = null;
    let lastHash = "";
    const anchors = Array.from(document.querySelectorAll('.a3s a'))
    .map(a => ({ href: a.href, text: (a.textContent || '').trim() }))
    .slice(0, 50); // sécurité
  
    const senderName = document.querySelector('.gD')?.innerText || '';
    return { subject, sender, senderName, body, links, attachments, anchors };

    // === Seuil depuis le popup ===
    chrome.storage?.sync?.get({ threshold: DEFAULT_THRESHOLD }, ({ threshold: t }) => {
      threshold = t;
      console.log("[AntiPhish] threshold from storage =", threshold);
    });

    // === Utils ===
    function debounce(fn, delay) {
      let to;
      return function (...args) {
        clearTimeout(to);
        to = setTimeout(() => fn.apply(this, args), delay);
      };
    }

    async function waitForEmailReady(timeout = 4000) {
      const t0 = performance.now();
      while (performance.now() - t0 < timeout) {
        const subj = document.querySelector(SUBJECT_SELECTOR);
        const body = document.querySelector(BODY_SELECTOR);
        const hasText = (subj?.innerText?.trim()?.length || 0) + (body?.innerText?.trim()?.length || 0) > 5;
        if (subj && body && hasText) return true;
        await new Promise(r => setTimeout(r, 100));
      }
      return false;
    }

    function computeHash({ subject = "", sender = "", body = "" }) {
      return `${subject}||${sender}||${body.length}`;
    }

    // === Extraction DOM ===
    function extractEmailData() {
      try {
        const subject = document.querySelector(SUBJECT_SELECTOR)?.innerText || "";
        const sender  = document.querySelector(SENDER_SELECTOR)?.getAttribute("email") || "";
        const body    = document.querySelector(BODY_SELECTOR)?.innerText || "";
        const links   = Array.from(document.querySelectorAll(LINK_SELECTOR)).map(a => a.href);
        const attachments = Array.from(document.querySelectorAll(ATTACHMENT_SELECTOR)).map(el =>
          el.getAttribute("download_url")?.split(":").pop()
        );
        if (!subject && !body) return null;
        return { subject, sender, body, links, attachments };
      } catch (err) {
        console.warn("[AntiPhish] extract error:", err);
        return null;
      }
    }

    // === Bannière flottante (iFrame) ===
    function injectAlertBanner(scoreDetails, emailData) {
      if (document.querySelector(BANNER_ID)) return;

      const iframe = document.createElement("iframe");
      iframe.id  = "anti-phish-banner";
      iframe.src = chrome.runtime.getURL("ui/warning_banner.html");
      iframe.style.cssText = `
        position: fixed;
        inset: auto 0 0 auto;     /* bottom:0; right:0 */
        display: block;
        vertical-align: bottom;
        margin: 0; padding: 0;
        width: 300px;             /* largeur alignée avec .wrap */
        height: 56px;             /* hauteur d'entête; sera ajustée via postMessage */
        border: 0;
        background: transparent;
        z-index: 2147483647;
        pointer-events: auto;
      `;
      // Alternative avec safe-area (encoches) :
      // iframe.style.right  = 'env(safe-area-inset-right, 0)';
      // iframe.style.bottom = 'env(safe-area-inset-bottom, 0)';

      document.body.appendChild(iframe);

      iframe.onload = () => {
        iframe.contentWindow?.postMessage(
          { ...scoreDetails, sender: emailData?.sender || "" },
          "*"
        );
      };
    }

    function upsertBanner(scoreDetails, emailData) {
      const frame = document.getElementById("anti-phish-banner");
      if (frame?.contentWindow) {
        frame.contentWindow.postMessage(
          { ...scoreDetails, sender: emailData?.sender || "" },
          "*"
        );
      } else {
        injectAlertBanner(scoreDetails, emailData);
      }
    }

    function removeBannerIfAny() {
      const existing = document.querySelector(BANNER_ID);
      if (existing) existing.remove();
    }

    // === Ignore expéditeur ===
    async function shouldIgnoreSender(sender) {
      return new Promise(resolve => {
        chrome.storage.sync.get({ ignoredSenders: [] }, ({ ignoredSenders }) => {
          resolve(ignoredSenders.includes((sender || "").toLowerCase()));
        });
      });
    }
    function addIgnoredSender(sender) {
      chrome.storage.sync.get({ ignoredSenders: [] }, ({ ignoredSenders }) => {
        const set = new Set(ignoredSenders);
        set.add((sender || "").toLowerCase());
        chrome.storage.sync.set({ ignoredSenders: Array.from(set) });
      });
    }

    // === Surbrillance prudente ===
    let highlightsOn = false;
    function highlightRisks({ body }) {
      const root = document.querySelector(".a3s");
      if (!root) return;
      unhighlightRisks();

      // Liens suspects
      root.querySelectorAll('a[href]').forEach(a => {
        if (/bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rebrand\.ly|\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top|\.zip|\.mov/i.test(a.href)) {
          a.style.outline = "2px solid #d32f2f";
          a.dataset.apMarked = "1";
          a.title = (a.title || "") + " [Lien suspect]";
        }
      });

      // Mots/phrases à risque
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
      const riskyRe = /\b(urgent|urgence|immédiatement|immediatement|cliquez|cliquer|vérifiez|verifiez|compte\s*(bloqué|bloque|suspendu))\b/gi;
      const extRe   = /\b[\w.-]+\.(exe|js|vbs|scr|bat|cmd|ps1|apk|html?|hta|zip|rar|7z)\b/gi;
      const nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);

      nodes.forEach(node => {
        const txt = node.nodeValue;
        if (!txt) return;
        if (!riskyRe.test(txt) && !extRe.test(txt)) return;
        const span = document.createElement("span");
        span.style.background    = "rgba(243, 156, 18, 0.35)";
        span.style.padding       = "0 2px";
        span.style.borderRadius  = "2px";
        span.dataset.apMarked    = "1";
        span.textContent         = txt;
        node.parentNode.replaceChild(span, node);
      });
      highlightsOn = true;
    }
    function unhighlightRisks() {
      const root = document.querySelector(".a3s");
      if (!root) return;
      root.querySelectorAll('[data-ap-marked="1"]').forEach(el => {
        if (el.tagName === "A") {
          el.style.outline = "";
          el.removeAttribute("data-ap-marked");
        } else if (el.firstChild && el.childNodes.length === 1 && el.firstChild.nodeType === Node.TEXT_NODE) {
          el.replaceWith(el.firstChild);
        } else {
          el.style.background = "";
          el.removeAttribute("data-ap-marked");
        }
      });
      highlightsOn = false;
    }

    // === Callback d’analyse (fiable) ===
    const handleDomChange = debounce(async () => {
      const ready = await waitForEmailReady(4000);
      if (!ready) {
        removeBannerIfAny(); // si on est sur la liste -> aucune bannière
        console.log("[AntiPhish] email not ready");
        return;
      }

      const emailData = extractEmailData();
      if (!emailData) {
        removeBannerIfAny();
        console.log("[AntiPhish] no emailData");
        return;
      }

      const h = computeHash(emailData);
      if (h === lastHash) return; // même thread; évite ré-analyses inutiles
      lastHash = h;
      lastEmailData = emailData;

      if (await shouldIgnoreSender(emailData.sender)) {
        removeBannerIfAny();
        return;
      }

      const scoreDetails = analyzeEmail(emailData);
      console.log("[AntiPhish] score=", scoreDetails.score, "threshold=", threshold);

      if (scoreDetails.score >= threshold) {
        upsertBanner(scoreDetails, emailData);
      } else {
        removeBannerIfAny();
      }
    }, 200);

    // === Observer DOM + démarrage immédiat ===
    const observer = new MutationObserver(() => handleDomChange());
    function waitForGmailAndStart() {
      const target = document.querySelector(GMAIL_SELECTOR);
      if (target) {
        observer.observe(target, { childList: true, subtree: true });
        console.log("Gmail DOM observer initialized");
        setTimeout(() => handleDomChange(), 80);
      } else {
        setTimeout(waitForGmailAndStart, 300);
      }
    }

    // === Hook navigation SPA + capture clics sur threads ===
    (function hookRouteChanges() {
      const fire = () => setTimeout(() => {
        observer.disconnect();
        waitForGmailAndStart();
      }, 100);

      const wrap = (fn) => function (...args) {
        const r = fn.apply(this, args);
        window.dispatchEvent(new Event("locationchange"));
        return r;
      };

      history.pushState    = wrap(history.pushState);
      history.replaceState = wrap(history.replaceState);
      window.addEventListener("popstate", () =>
        window.dispatchEvent(new Event("locationchange"))
      );
      window.addEventListener("locationchange", fire);

      // Capture des clics sur la liste des mails (déclenche l'analyse plus tôt)
      document.addEventListener("click", (e) => {
        if (e.target.closest?.('tr.zA, div.Cp tr, .UI [role="listitem"]')) {
          setTimeout(() => handleDomChange(), 150);
        }
      }, true);
    })();

    // === Messages depuis la bannière (iFrame) ===
    if (!window.__antiPhishUXListener) {
      window.addEventListener("message", async (evt) => {
        // Resize demandé par l'iframe pour coller au bas (pas de scroll interne)
        if (evt.data && evt.data.type === "apBannerResize") {
          const frame = document.getElementById("anti-phish-banner");
          if (frame) {
            frame.style.height = Math.ceil(evt.data.height) + "px";
          }
        }

        if (evt.data === "manualAnalyze") {
          const data = extractEmailData();
          if (!data) return;
          lastEmailData = data;
          const details = analyzeEmail(data);
          const frame = document.getElementById("anti-phish-banner");
          if (frame?.contentWindow) {
            frame.contentWindow.postMessage(
              { ...details, sender: data.sender || "" },
              "*"
            );
          }
        }

        if (evt.data === "toggleHighlights") {
          if (!lastEmailData) return;
          highlightsOn ? unhighlightRisks() : highlightRisks(lastEmailData);
        }

        if (evt.data === "dismissBanner") {
          removeBannerIfAny();
          unhighlightRisks();
        }

        if (evt.data && evt.data.type === "ignoreSender") {
          addIgnoredSender(evt.data.sender || lastEmailData?.sender || "");
          removeBannerIfAny();
          unhighlightRisks();
          console.log("[AntiPhish] Sender ignored:", evt.data.sender);
        }

        if (evt.data === "deepScanRequest") {
          // Pas de backend pour le moment
          console.log("[AntiPhish] Deep scan clicked (no backend configured)");
        }
      });
      window.__antiPhishUXListener = true;
    }

    // === Go ===
    waitForGmailAndStart();
  })
  .catch(err => console.error("Failed to load local_scanner.js", err));