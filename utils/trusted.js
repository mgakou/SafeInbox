// ==========================================================
// 🛡️ SafeInbox – Gestion centralisée des expéditeurs de confiance
// Fusionne : base globale, whitelist utilisateur et liste ignorée
// ==========================================================

/**
 * 🔹 Charge et fusionne :
 * - la base globale (trusted_senders.json)
 * - la whitelist utilisateur (chrome.storage.sync)
 * - la liste des expéditeurs ignorés (ignoredSenders)
 */
export async function getTrustedBase() {
  try {
    const response = await fetch(chrome.runtime.getURL("utils/trusted_senders.json"));
    const base = await response.json();

    const {
      whitelistEmails = [],
      whitelistDomains = [],
      ignoredSenders = [],
    } = await chrome.storage.sync.get([
      "whitelistEmails",
      "whitelistDomains",
      "ignoredSenders",
    ]);

    // Fusion dédoublonnée et normalisée
    const emails = new Set([
      ...(base.emails || []),
      ...whitelistEmails.map((e) => e.toLowerCase()),
      ...ignoredSenders.map((e) => e.toLowerCase()),
    ]);

    const domains = new Set([
      ...Object.values(base.domains || {}).flat(),
      ...whitelistDomains.map((d) => d.toLowerCase()),
    ]);

    return { emails, domains, ignoredSenders };
  } catch (err) {
    console.error("[SafeInbox] ❌ Erreur chargement trusted_senders.json :", err);
    return { emails: new Set(), domains: new Set(), ignoredSenders: [] };
  }
}

/**
 * 🔹 Vérifie si un expéditeur est considéré comme "trusted"
 * @param {string} email - adresse email complète
 * @returns {Promise<{trusted:boolean, source:string, level:string}>}
 */
export async function checkSenderTrusted(email) {
  if (!email) return { trusted: false, source: "none", level: "none" };

  const e = email.toLowerCase().trim();
  const domain = e.split("@")[1] || "";
  const { emails, domains, ignoredSenders } = await getTrustedBase();

  // 1️⃣ Email exact dans la base ou whitelist
  if (emails.has(e)) {
    return { trusted: true, source: "trusted list", level: "email" };
  }

  // 2️⃣ Domaine reconnu
  if (domains.has(domain)) {
    return { trusted: true, source: "trusted list", level: "domain" };
  }

  // 3️⃣ Expéditeur explicitement ignoré (ajouté par utilisateur)
  if (ignoredSenders.includes(e)) {
    return { trusted: true, source: "ignored list", level: "user" };
  }

  // 4️⃣ Sinon, non reconnu
  return { trusted: false, source: "none", level: "none" };
}

/**
 * 🔹 Ajoute un expéditeur à la liste d'ignore (persisté via chrome.storage.sync)
 * @param {string} senderEmail
 */
export function addIgnoredSender(senderEmail) {
  const email = (senderEmail || "").toLowerCase().trim();
  if (!email.includes("@")) return;

  const domain = email.split("@")[1];

  chrome.storage.sync.get(
    { whitelistEmails: [], whitelistDomains: [], ignoredSenders: [] },
    ({ whitelistEmails, whitelistDomains, ignoredSenders }) => {
      const emails = new Set(whitelistEmails.map((e) => e.toLowerCase()));
      const domains = new Set(whitelistDomains.map((d) => d.toLowerCase()));
      const ignored = new Set(ignoredSenders.map((e) => e.toLowerCase()));

      emails.add(email);
      domains.add(domain);
      ignored.add(email);

      chrome.storage.sync.set({
        whitelistEmails: Array.from(emails),
        whitelistDomains: Array.from(domains),
        ignoredSenders: Array.from(ignored),
      });

      console.log(`[SafeInbox] ✅ Expéditeur ajouté à la liste d’ignore : ${email}`);
    }
  );
}

/**
 * 🔹 Supprime un expéditeur (ou domaine) de la liste d’ignore
 * @param {string} target - email ou domaine
 */
export async function removeIgnoredSender(target) {
  const key = (target || "").toLowerCase().trim();

  const {
    whitelistEmails = [],
    whitelistDomains = [],
    ignoredSenders = [],
  } = await chrome.storage.sync.get([
    "whitelistEmails",
    "whitelistDomains",
    "ignoredSenders",
  ]);

  const emails = new Set(whitelistEmails.map((e) => e.toLowerCase()));
  const domains = new Set(whitelistDomains.map((d) => d.toLowerCase()));
  const ignored = new Set(ignoredSenders.map((e) => e.toLowerCase()));

  emails.delete(key);
  domains.delete(key);
  ignored.delete(key);

  await chrome.storage.sync.set({
    whitelistEmails: Array.from(emails),
    whitelistDomains: Array.from(domains),
    ignoredSenders: Array.from(ignored),
  });

  console.log(`[SafeInbox] 🗑️ Expéditeur retiré de la liste d’ignore : ${key}`);
}

/**
 * 🔹 Vide complètement la liste des expéditeurs ignorés
 */
export async function clearIgnoredSenders() {
  await chrome.storage.sync.set({ ignoredSenders: [] });
  console.log("[SafeInbox] 🧹 Liste des expéditeurs ignorés vidée");
}

/**
 * 🔹 Récupère toutes les listes utilisateur (emails, domaines, ignorés)
 */
export async function getUserWhitelist() {
  const {
    whitelistEmails = [],
    whitelistDomains = [],
    ignoredSenders = [],
  } = await chrome.storage.sync.get([
    "whitelistEmails",
    "whitelistDomains",
    "ignoredSenders",
  ]);
  return {
    whitelistEmails,
    whitelistDomains,
    ignoredSenders,
  };
}