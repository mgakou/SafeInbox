// utils/local_scanner.js
// Heuristiques locales pour détection de signaux faibles de phishing

// Mots/expressions fréquents (FR/EN + variantes sans accents)
const riskyKeywords = new Set([
  "urgent", "urgence", "immediatement", "immédiatement",
  "compte bloqué", "compte bloque", "compte suspendu", "suspendu",
  "paiement", "payer", "virement", "remboursement",
  "mot de passe", "password",
  "confidentiel", "verification", "vérification", "verifiez", "vérifiez",
  "mise a jour", "mise à jour", "mise a jour de securite", "mise à jour de sécurité",
  "securite", "sécurité",
  "facture", "invoice",
  "cliquer ici", "cliquez", "cliquer", "click here",
  "confirmez", "confirmer", "validez", "valider",
  "identite", "identité",
]);

// Raccourcisseurs & domaines/tld souvent abusés
const suspiciousDomains = new Set([
  // shorteners
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly", "buff.ly", "ow.ly", "s.id", "shorte.st", "adf.ly", "lnkd.in",
  // tlds
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".icu", ".cam", ".click", ".info", ".rest", ".support", ".work", ".zip", ".mov"
]);

// Extensions dangereuses (pièces jointes ou mentionnées)
const dangerousExtensions = new Set([
  ".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1", ".jar",
  ".apk", ".iso", ".img", ".lnk", ".msi", ".reg", ".url",
  ".html", ".htm", ".hta",
  ".zip", ".rar", ".7z", ".dmg"
]);

// Marques/organismes souvent ciblés (utile combiné avec pression/urgence)
const brandNames = new Set([
  "microsoft", "office 365", "outlook", "google", "gmail", "apple", "icloud",
  "amazon", "paypal", "dhl", "fedex", "ups", "bank", "banque",
  "orange", "sfr", "free", "laposte", "impots", "ameli"
]);

export function analyzeEmail({ subject = "", sender = "", body = "", links = [], attachments = [] }) {
  let score = 0;
  const reasons = [];

  const textContent = `${subject} ${body}`.toLowerCase();

  // 0) Caractères invisibles/homographes simples
  if (/[\u200B-\u200D\uFEFF]/.test(body)) {
    score += 5;
    reasons.push("Caractères invisibles suspects dans le texte");
  }

  // 1) Mots-clés directs (Set de base)
  for (const kw of riskyKeywords) {
    if (textContent.includes(kw)) {
      score += 7;
      reasons.push(`Mot/phrase à risque: "${kw}"`);
    }
  }

  // 1bis) Regex plus robustes (variantes & pressions)
  const riskyRegexes = [
    /\burgent(e|ement|emment)?\b/i,
    /\b(cliquez|cliquer|clique|cliquer ici|click here)\b/i,
    /\b(v[ée]rif(iez|ication)|verification)\b/i,
    /\bmise\s*(a|à)\s*jour(\s*de\s*(la\s*)?s[ée]curit[ée])?\b/i,
    /\b(compte|acc[èe]s)\s*(bloqu[ée]|suspendu|desactiv[ée]|désactiv[ée])\b/i,
    /\b(derni(è|e)re|ultime)\s*chance\b/i,
    /\b(24|48)\s*h(eures?)?\b/i
  ];
  let pressureHit = false;
  for (const rx of riskyRegexes) {
    if (rx.test(textContent)) {
      score += 7;
      pressureHit = true;
      reasons.push(`Expression à risque: ${rx.source}`);
    }
  }

  // 2) URL brute dans le corps (même sans <a>)
  if (/\bhttps?:\/\/[^\s<>")']+/i.test(body)) {
    score += 10;
    reasons.push("URL présente dans le texte");
  }

  // 3) Analyse des liens href (<a href=...>)
  for (const link of links || []) {
    const l = String(link || "");
    // shorteners & TLD list
    for (const domain of suspiciousDomains) {
      if (l.includes(domain)) {
        score += 10;
        reasons.push(`Lien suspect (domaine/TLD): ${l}`);
        break;
      }
    }
    try {
      const u = new URL(l);
      const host = (u.hostname || "").toLowerCase();
      if (host.startsWith("xn--")) {
        score += 12;
        reasons.push(`Domaine punycode/homographe: ${host}`);
      }
      // TLD haut risque supplémentaires
      if (/\.(zip|mov)$/i.test(host)) {
        score += 10;
        reasons.push(`TLD à risque: ${host}`);
      }
    } catch { /* ignore invalid URLs */ }
  }

  // 4) Extensions dangereuses mentionnées dans le corps (ex: fichier.exe)
  const extRe = /\b[\w.-]+\.(exe|js|vbs|scr|bat|cmd|ps1|apk|jar|iso|img|lnk|msi|reg|url|html?|hta|zip|rar|7z|dmg)\b/ig;
  const foundInBody = new Set();
  for (const m of body.matchAll(extRe)) {
    const hit = m[0].toLowerCase();
    if (!foundInBody.has(hit)) {
      foundInBody.add(hit);
      score += 15;
      reasons.push(`Extension dangereuse mentionnée: ${hit}`);
    }
  }

  // 5) Pièces jointes dangereuses (et double-extension)
  for (const file of attachments || []) {
    const lower = String(file || "").toLowerCase();
    for (const ext of dangerousExtensions) {
      if (lower.endsWith(ext)) {
        score += 15;
        reasons.push(`Pièce jointe potentiellement dangereuse: ${file}`);
        break;
      }
    }
    if (/\.(pdf|docx?|xlsx?|pptx?|jpg|png)\.(exe|js|vbs|scr|bat|cmd|ps1)$/i.test(lower)) {
      score += 20;
      reasons.push(`Double extension dangereuse: ${file}`);
    }
  }

  // 6) Cohérence adresse expéditeur
  try {
    const [localPart = "", domain = ""] = sender.split("@");
    if (!domain) {
      score += 5;
      reasons.push("Adresse expéditeur non analysable");
    } else if (!domain.toLowerCase().includes(localPart.toLowerCase())) {
      score += 10;
      reasons.push("Incohérence entre le nom local et le domaine de l'expéditeur");
    }
  } catch {
    score += 5;
    reasons.push("Erreur lors de l'analyse de l'adresse expéditeur");
  }

  // 7) Marque + pression/urgence = signal fort
  for (const b of brandNames) {
    if (textContent.includes(b) && pressureHit) {
      score += 8;
      reasons.push(`Marque citée + urgence/pression: ${b}`);
      break;
    }
  }

  // Déduplication des raisons et clamp du score
  const uniqueReasons = Array.from(new Set(reasons));
  return { score: Math.min(score, 100), reasons: uniqueReasons };
}
