// ==========================================================
// 🛡️ SafeInbox – Trusted Senders (EMAIL-ONLY)
// - Trusted : email exact uniquement (base + whitelistEmails)
// - Ignored : mécanisme séparé (ignoredSenders)
// ==========================================================

/**
 * Charge la base trusted globale + la whitelist utilisateur
 * (emails exacts uniquement)
 */
export async function getTrustedEmails() {
  try {
    const response = await fetch(
      chrome.runtime.getURL("utils/trusted_senders.json")
    );
    const base = await response.json();

    const { whitelistEmails = [] } = await chrome.storage.sync.get([
      "whitelistEmails",
    ]);

    return new Set([
      ...(base.emails || []).map((e) => e.toLowerCase()),
      ...whitelistEmails.map((e) => e.toLowerCase()),
    ]);
  } catch (err) {
    console.error("[SafeInbox] Failed to load trusted emails:", err);
    return new Set();
  }
}

/**
 * Vérifie si un expéditeur est trusted
 * 👉 EMAIL EXACT UNIQUEMENT
 */
export async function checkSenderTrusted(email) {
  if (!email) {
    return { trusted: false, source: "none", level: "none" };
  }

  const e = email.toLowerCase().trim();
  const trustedEmails = await getTrustedEmails();

  if (trustedEmails.has(e)) {
    return { trusted: true, source: "trusted list", level: "email" };
  }

  return { trusted: false, source: "none", level: "none" };
}

/**
 * Ajoute un expéditeur à la liste IGNORÉE
 * ⚠️ N'impacte PAS trusted
 */
export function addIgnoredSender(senderEmail) {
  const email = (senderEmail || "").toLowerCase().trim();
  if (!email.includes("@")) return;

  chrome.storage.sync.get(
    { ignoredSenders: [] },
    ({ ignoredSenders }) => {
      const set = new Set(ignoredSenders.map((e) => e.toLowerCase()));
      set.add(email);

      chrome.storage.sync.set({
        ignoredSenders: Array.from(set),
      });

      console.log(`[SafeInbox] Ignored sender added: ${email}`);
    }
  );
}

/**
 * Supprime un expéditeur de la liste ignorée
 */
export async function removeIgnoredSender(email) {
  const key = (email || "").toLowerCase().trim();

  const { ignoredSenders = [] } = await chrome.storage.sync.get([
    "ignoredSenders",
  ]);

  const set = new Set(ignoredSenders.map((e) => e.toLowerCase()));
  set.delete(key);

  await chrome.storage.sync.set({
    ignoredSenders: Array.from(set),
  });

  console.log(`[SafeInbox] Ignored sender removed: ${key}`);
}

/**
 * Récupère la liste des expéditeurs ignorés
 */
export async function getIgnoredSenders() {
  const { ignoredSenders = [] } = await chrome.storage.sync.get([
    "ignoredSenders",
  ]);
  return ignoredSenders;
}