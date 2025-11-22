// ==========================================================
// 🛡️ SafeInbox – Content Script (Gmail)
// Analyse locale + Trusted Senders + Bannière d’avertissement
// ==========================================================

(async () => {
  try {
    // 1️⃣ Charger les modules en parallèle
    const [
      { checkSenderTrusted, addIgnoredSender },
      { analyzeEmail, loadRules, lightCheckEmail },
    ] = await Promise.all([
      import(chrome.runtime.getURL("utils/trusted.js")),
      import(chrome.runtime.getURL("utils/local_scanner.js")),
    ]);

    // 2️⃣ Charger les règles au démarrage
    await loadRules();
    console.log("[SafeInbox] Modules chargés (trusted + local_scanner)");

    // 3️⃣ Initialiser SafeInbox
    initSafeInbox({ checkSenderTrusted, addIgnoredSender, analyzeEmail, lightCheckEmail });
  } catch (err) {
    console.error("[SafeInbox] Échec du chargement des modules :", err);
  }
})();

// ==========================================================
// ⚙️ Initialisation principale
// ==========================================================
function initSafeInbox({ checkSenderTrusted, addIgnoredSender, analyzeEmail, lightCheckEmail }) {
  const GMAIL_SELECTOR = 'div[role="main"]';
  const SUBJECT_SELECTOR = 'h2.hP';
  const SENDER_SELECTOR = '.gD';
  const SENDER_NAME_SELECTOR = '.gD';
  const BODY_SELECTOR = '.a3s';
  const LINK_SELECTOR = '.a3s a';
  const ATTACHMENT_SELECTOR = '[download_url]';
  const BANNER_ID = '#anti-phish-banner';
  const DEFAULT_THRESHOLD = 40;

  // État interne
  let threshold = DEFAULT_THRESHOLD;
  let lastEmailData = null;
  let lastHash = "";
  let highlightsOn = false;

  // Charger le seuil depuis storage
  chrome.storage.sync.get({ threshold: DEFAULT_THRESHOLD }, ({ threshold: t }) => {
    threshold = t;
    console.log("[SafeInbox] Seuil initial =", threshold);
  });

  // ==========================================================
  // 🧩 Helpers
  // ==========================================================
  const debounce = (fn, delay) => {
    let to;
    return (...args) => {
      clearTimeout(to);
      to = setTimeout(() => fn.apply(this, args), delay);
    };
  };

  const waitForEmailReady = async (timeout = 4000) => {
    const t0 = performance.now();
    while (performance.now() - t0 < timeout) {
      const subj = document.querySelector(SUBJECT_SELECTOR);
      const body = document.querySelector(BODY_SELECTOR);
      const ready = subj && body && ((subj.innerText || "").trim().length + (body.innerText || "").trim().length > 5);
      if (ready) return true;
      await new Promise((r) => setTimeout(r, 100));
    }
    return false;
  };

  const computeHash = ({ subject = "", sender = "", body = "" }) => `${subject}||${sender}||${body.length}`;

  async function shouldIgnoreSender(sender) {
    return new Promise((resolve) => {
      chrome.storage.sync.get({ ignoredSenders: [] }, ({ ignoredSenders }) =>
        resolve(ignoredSenders.includes((sender || "").toLowerCase()))
      );
    });
  }

  // ==========================================================
  // ✉️ Extraction des données du mail
  // ==========================================================
  function extractEmailData() {
    try {
      const subject = document.querySelector(SUBJECT_SELECTOR)?.innerText || "";
      const sender = document.querySelector(SENDER_SELECTOR)?.getAttribute("email") || "";
      const senderName = document.querySelector(SENDER_NAME_SELECTOR)?.textContent?.trim() || "";
      const body = document.querySelector(BODY_SELECTOR)?.innerText || "";
      const links = Array.from(document.querySelectorAll(LINK_SELECTOR)).map((a) => a.href);
      const anchors = Array.from(document.querySelectorAll(LINK_SELECTOR)).map((a) => ({ href: a.href, text: a.textContent || "" }));
      const attachments = Array.from(document.querySelectorAll(ATTACHMENT_SELECTOR)).map((el) =>
        el.getAttribute("download_url")?.split(":").pop()
      );

      if (!subject && !body) return null;
      return { subject, sender, senderName, body, links, attachments, anchors };
    } catch (e) {
      console.warn("[SafeInbox] ⚠️ Erreur extraction :", e);
      return null;
    }
  }

  // ==========================================================
  // 🚨 Bannière d’alerte
  // ==========================================================
  function injectBanner(scoreDetails, emailData) {
    const iframe = document.createElement("iframe");
    iframe.id = "anti-phish-banner";
    iframe.src = chrome.runtime.getURL("ui/warning_banner.html");
    iframe.style.cssText = `
      position: fixed;
      inset: auto 0 0 auto;
      width: 320px;
      height: 56px;
      border: 0;
      background: transparent;
      z-index: 2147483647;
      pointer-events: auto;
    `;
    document.body.appendChild(iframe);

    iframe.onload = () =>
      iframe.contentWindow?.postMessage({ ...scoreDetails, sender: emailData?.sender || "" }, "*");
  }

  function upsertBanner(scoreDetails, emailData) {
    const frame = document.getElementById("anti-phish-banner");
    if (frame?.contentWindow)
      frame.contentWindow.postMessage({ ...scoreDetails, sender: emailData?.sender || "" }, "*");
    else injectBanner(scoreDetails, emailData);
  }

  const removeBanner = () => document.querySelector(BANNER_ID)?.remove();

  // ==========================================================
  // 🧠 Analyse principale
  // ==========================================================
  const handleDomChange = debounce(async () => {
    if (!(await waitForEmailReady())) return removeBanner();

    const emailData = extractEmailData();
    if (!emailData) return removeBanner();

    const h = computeHash(emailData);
    if (h === lastHash) return; // évite les re-analyses inutiles
    lastHash = h;
    lastEmailData = emailData;

    // Vérifie si l'expéditeur est ignoré
    if (await shouldIgnoreSender(emailData.sender)) return removeBanner();

    // Vérifie si expéditeur est de confiance
    const trust = await checkSenderTrusted(emailData.sender);
    if (trust.trusted) {
      console.log(`[SafeInbox] Expéditeur de confiance (${trust.level} - ${trust.source})`);
      const light = typeof lightCheckEmail === "function"
        ? await lightCheckEmail(emailData)
        : { score: 0 };
      if (light.score >= threshold) upsertBanner(light, emailData);
      else removeBanner();
      return;
    }

    // Analyse complète
    const scoreDetails = await analyzeEmail(emailData);
    console.log(`[SafeInbox] Score obtenu : ${scoreDetails.score} / seuil ${threshold}`);
    if (scoreDetails.score >= threshold) upsertBanner(scoreDetails, emailData);
    else removeBanner();
  }, 250);

  // ==========================================================
  // 👂 Listener des messages de la bannière (iframe UI)
  // ==========================================================
  window.addEventListener("message", async (evt) => {
    const data = evt.data;
    if (!data) return;

    // a) Analyse manuelle
    if (data === "manualAnalyze") {
      const fresh = extractEmailData();
      if (!fresh) return;
      const details = await analyzeEmail(fresh);
      const frame = document.getElementById("anti-phish-banner");
      frame?.contentWindow?.postMessage({ ...details, sender: fresh.sender || "" }, "*");
    }

    // b) Toggle surlignage
    if (data === "toggleHighlights") {
      highlightsOn = !highlightsOn;
      console.log(`[SafeInbox] Surlignage ${highlightsOn ? "activé" : "désactivé"}`);
    }

    // c) Fermer la bannière
    if (data === "dismissBanner") {
      removeBanner();
    }

    // d) Ignorer un expéditeur
    if (data.type === "ignoreSender") {
      const toIgnore = (data.sender || lastEmailData?.sender || "").toLowerCase();
      if (toIgnore) {
        addIgnoredSender(toIgnore);
        console.log("[SafeInbox] ✳️ Expéditeur ajouté à la liste d’ignore :", toIgnore);
      }
      removeBanner();
    }

    // e) Deep scan (à venir)
    if (data === "deepScanRequest") {
      console.log("[SafeInbox] Deep scan déclenché (backend à venir)");
    }
  });

  // ==========================================================
  //  Réception des mises à jour depuis le popup
  // ==========================================================
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "thresholdUpdated") {
      threshold = msg.newThreshold;
      console.log(`[SafeInbox]  Seuil mis à jour via popup : ${threshold}`);
      handleDomChange();
    }

    if (msg.type === "ignoreListUpdated") {
      console.log("[SafeInbox]  Liste ignorée mise à jour → relance de l'analyse");
      handleDomChange();
    }
  });

  // ==========================================================
  // 🕵️‍♂️ Observer Gmail DOM
  // ==========================================================
  const observer = new MutationObserver(() => handleDomChange());
  const startObserver = () => {
    const t = document.querySelector(GMAIL_SELECTOR);
    if (t) {
      observer.observe(t, { childList: true, subtree: true });
      setTimeout(handleDomChange, 150);
      console.log("[SafeInbox] 👀 Gmail DOM observer initialisé");
    } else setTimeout(startObserver, 300);
  };

  // ==========================================================
  // 🚀 Démarrage
  // ==========================================================
  startObserver();
}