
// utils/local_scanner.js — moteur local renforcé (rapide & sans réseau)
/* ======================== Dictionnaires ======================== */
const riskyKeywords = new Set([
  // pression / sécurité / finance (FR)
  "urgent","urgence","immédiatement","immediatement","immédiat","immediat",
  "compte bloqué","compte suspendu","vérifiez","verifiez","confidentiel",
  "mot de passe","paiement","facture","remboursement","mise à jour","mise a jour",
  "sécurité","securite","cliquer ici","cliquez","valider","confirmer","identité",
  "dernière chance","dernier avertissement","sans délai",
  // EN (courant)
  "immediately","account locked","verify","password","payment","invoice",
  "refund","update","security","click here","confirm","identity","last warning"
]);

// Expressions plus ciblées
const CTA_RE        = /\b(ici|here|cliquez(?:\s+ici)?|click(?:\s+here)?|open link)\b/i;
const PRESSURE_RE   = /\b(24\s*h|48\s*h|72\s*h|dans\s+\d{1,2}\s*(heures?|jours?)|dernier(?:\s+avertissement|e chance)|immédiatement|immediatement|sans délai|asap)\b/i;
const CRED_RE       = /\b(mot\s*de\s*passe|password|identifiants?|credentials?|code\s*de\s*vérification|otp|2fa|authenticator)\b/i;
const BILLING_RE    = /\b(facture|invoice|paiement|payment|remboursement|refund|virement|wire|iban|rib)\b/i;

// raccourcisseurs / TLD chauds
const shorteners = new Set([
  "bit.ly","tinyurl.com","t.co","is.gd","cutt.ly","rebrand.ly","rb.gy","lnkd.in",
  "goo.gl","ow.ly","s.id","shrtco.de","linktr.ee"
]);
const riskyTLD = new Set(["zip","mov","xyz","top","gq","tk","ml","ga","cf","click","work","shop"]);

// extensions à risque
const dangerousExt = new Set([
  "exe","js","vbs","scr","bat","cmd","ps1","apk","jar","hta","html","htm",
  "lnk","iso","img","dll","com","pif","wsf","svg","ace","rar","7z","zip","docm","xlsm","pptm"
]);

// marques fréquentes → domaines officiels (échantillon, extensible)
const brandDomains = {
  "paypal": ["paypal.com"],
  "google": ["google.com","accounts.google.com"],
  "microsoft": ["microsoft.com","live.com","outlook.com"],
  "apple": ["apple.com","icloud.com"],
  "amazon": ["amazon.fr","amazon.com"],
  "netflix": ["netflix.com"],
  "laposte": ["laposte.fr","laposte.net"],
  "sfr": ["sfr.fr"],
  "orange": ["orange.fr"],
  "societe generale": ["societegenerale.fr","sg.fr"],
  "banque populaire": ["banque-populaire.fr","bpce.fr"]
};

// petite whitelist (réduit le score si tout est “officiel”)
const trusted = new Set([
  "google.com","accounts.google.com","microsoft.com","apple.com","icloud.com",
  "amazon.fr","amazon.com","github.com","gitlab.com","stripe.com","paypal.com"
]);

/* ======================== Helpers ======================== */
const SLD_EXCEPTIONS = new Set(["co.uk","ac.uk","gov.uk","com.au","com.br","com.mx"]);
const MIX_CYRILLIC = /[\u0400-\u04FF]/;   // lettres cyrilliques
const MIX_GREEK    = /[\u0370-\u03FF]/;

function normalize(text="") {
  return text.normalize("NFD").replace(/\p{Diacritic}/gu,"").toLowerCase();
}
function getHostname(u="") {
  try { return new URL(u).hostname.toLowerCase(); } catch { return ""; }
}
function isIPAddress(host="") {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || /^[a-f0-9:]+$/i.test(host);
}
function baseDomain(host="") {
  const parts = host.split(".").filter(Boolean);
  if (parts.length < 2) return host;
  const lastTwo = parts.slice(-2).join(".");
  if (SLD_EXCEPTIONS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}
function lev(a="", b="") { // Levenshtein léger
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  const dp = new Array(b.length + 1).fill(0).map((_,i)=>i);
  for (let i=1;i<=a.length;i++){
    let prev = i-1, cur = i;
    for (let j=1;j<=b.length;j++){
      const tmp = dp[j];
      dp[j] = Math.min(
        dp[j] + 1,
        cur + 1,
        prev + (a[i-1] === b[j-1] ? 0 : 1)
      );
      prev = tmp; cur = dp[j];
    }
  }
  return dp[b.length];
}
function hasDoubleExtension(name="") {
  const parts = name.toLowerCase().split(".");
  if (parts.length < 3) return false;
  const last = parts.pop();
  return dangerousExt.has(last); // *.pdf.exe → last=exe
}
function manyExclamations(text=""){ return (text.match(/!/g)||[]).length >= 3; }
function allCapsRatio(text=""){
  const words = text.split(/\s+/).filter(w=>w.length>=3);
  const caps  = words.filter(w => /^[A-ZÀÂÄÇÉÈÊËÏÎÔÖÙÛÜŸ-]+$/.test(w)).length;
  return words.length ? caps / words.length : 0;
}
function subdomainDepth(host=""){ return Math.max(0, host.split(".").filter(Boolean).length - 2); }
function hasUserInfo(url=""){ try { const u=new URL(url); return !!(u.username || u.password); } catch { return false; } }
function pathLooksPhishy(url=""){
  try {
    const u = new URL(url);
    const p = (u.pathname + " " + u.search).toLowerCase();
    if (/(login|signin|connect|verify|update|password|reset|secure|confirm)/.test(p)) return true;
    if (/[A-Za-z0-9+/]{24,}={0,2}/.test(p)) return true; // base64-ish
  } catch {}
  return false;
}

/* ======================== Analyse principale ======================== */
export function analyzeEmail({ subject="", sender="", body="", links=[], attachments=[], anchors=[] , senderName="" }) {
  // anchors: [{href, text}], senderName: "Affichage" si dispo
  let score = 0;
  const reasons = [];

  const text = normalize(`${subject} ${body}`);
  const subj = normalize(subject);
  const sndr = (sender||"").toLowerCase();

  /* --- 1) Ton et sémantique --- */
  for (const k of riskyKeywords) {
    if (text.includes(k)) { score += 5.5; reasons.push(`Mot/phrase à risque: "${k}"`); }
  }
  if (CTA_RE.test(body))       { score += 4; reasons.push("Appel à l'action générique (cliquer ici / here)"); }
  if (PRESSURE_RE.test(body))  { score += 6; reasons.push("Pression temporelle / délai court"); }
  if (CRED_RE.test(body))      { score += 6; reasons.push("Demande d'identifiants / code de vérification"); }
  if (BILLING_RE.test(body))   { score += 4; reasons.push("Thème financier/billing présent"); }
  if (manyExclamations(subject) || manyExclamations(body)) {
    score += 4; reasons.push("Ponctuation alarmiste (plusieurs '!')");
  }
  if (allCapsRatio(subject) > 0.4) {
    score += 4; reasons.push("Sujet majoritairement en MAJUSCULES");
  }

  /* --- 2) Caractères confusables / punycode --- */
  if (MIX_CYRILLIC.test(sndr) || MIX_GREEK.test(sndr) || MIX_CYRILLIC.test(text) || MIX_GREEK.test(text)) {
    score += 6; reasons.push("Caractères non latins potentiellement confusables");
  }

  /* --- 3) Analyse des liens (technique & sémantique) --- */
  const linkList = Array.isArray(links) ? links : [];
  let allLinksTrusted = linkList.length > 0; // présume “trusted” puis infirme

  for (const url of linkList) {
    const host = getHostname(url);
    if (!host) { allLinksTrusted = false; continue; }

    const bd = baseDomain(host);
    if (!trusted.has(bd)) allLinksTrusted = false;

    if (shorteners.has(host)) { score += 8; reasons.push(`Raccourcisseur d’URL: ${host}`); }
    const tld = host.split(".").pop();
    if (tld && riskyTLD.has(tld)) { score += 6; reasons.push(`TLD potentiellement risqué: .${tld}`); }
    if (isIPAddress(host))        { score += 10; reasons.push(`Lien vers IP directe: ${host}`); }
    if (/^http:\/\//i.test(url))  { score += 3; reasons.push("Lien non chiffré (http)"); }
    if (/^data:/i.test(url))      { score += 10; reasons.push("Lien data: potentiellement obfusqué"); }
    if (hasUserInfo(url))         { score += 8; reasons.push("URL avec userinfo (user@host)"); }
    if (subdomainDepth(host) >= 3){ score += 4; reasons.push(`Sous-domaine profond: ${host}`); }
    if (pathLooksPhishy(url))     { score += 6; reasons.push("Chemin/paramètres typiques d’hameçonnage"); }

    // look-alike de marque sur le DOMAINE du lien
    const mentioned = Object.keys(brandDomains).filter(b => text.includes(b) || subj.includes(b));
    for (const b of mentioned) {
      const official = brandDomains[b].map(d => baseDomain(d));
      const near     = official.some(d => d === bd || lev(d, bd) <= 2);
      if (!near) {
        score += 10; reasons.push(`Marque "${b}" citée mais lien vers ${bd}`);
      }
    }
  }

  // 3bis) Texte du lien ↔ domaine du href (si anchors fournis)
  for (const a of (anchors || [])) {
    const host = getHostname(a.href);
    if (!host) continue;
    const textDom = (a.text || "").toLowerCase().match(/([a-z0-9.-]+\.[a-z]{2,})/);
    if (textDom) {
      const textBase = baseDomain(textDom[1]);
      const hrefBase = baseDomain(host);
      if (textBase && hrefBase && textBase !== hrefBase) {
        score += 10; reasons.push(`Texte du lien affiche ${textBase} → pointe vers ${hrefBase}`);
      }
    }
    // bouton “ici / here” pointant hors marque officielle
    if (CTA_RE.test(a.text || "") && !trusted.has(baseDomain(host))) {
      score += 4; reasons.push(`CTA générique pointe vers ${baseDomain(host)}`);
    }
  }

  /* --- 4) Pièces jointes --- */
  for (const file of (attachments || [])) {
    const lower = (file || "").toLowerCase();
    const ext   = lower.split(".").pop();
    if (dangerousExt.has(ext)) {
      score += 12; reasons.push(`Pièce jointe à risque: ${file}`);
    }
    if (hasDoubleExtension(lower)) {
      score += 12; reasons.push(`Double extension suspecte: ${file}`);
    }
  }
  // combo texte → “mot de passe” + archive jointe
  if (CRED_RE.test(body) && (attachments || []).some(f => /\.zip|\.rar|\.7z/i.test(f || ""))) {
    score += 6; reasons.push("Archive jointe + mention de mot de passe");
  }

  /* --- 5) Expéditeur --- */
  try {
    const [localPart="", domainRaw=""] = sndr.split("@");
    const domain = (domainRaw||"").toLowerCase();
    if (!domain) {
      score += 5; reasons.push("Adresse expéditeur non analysable");
    } else {
      // a) incohérence locale
      if (localPart && !domain.includes(localPart.slice(0,5))) {
        score += 4; reasons.push("Incohérence nom local/domaine");
      }
      // b) nom d’affichage contient une marque mais domaine pas officiel
      if (senderName) {
        const n = normalize(senderName);
        const mentioned = Object.keys(brandDomains).filter(b => n.includes(b));
        if (mentioned.length) {
          const bd = baseDomain(domain);
          for (const b of mentioned) {
            const official = brandDomains[b].map(d => baseDomain(d));
            const near = official.some(d => d === bd || lev(d, bd) <= 2);
            if (!near) {
              score += 10; reasons.push(`Nom affiche la marque "${b}" mais domaine expéditeur = ${bd}`);
            }
          }
        }
      }
    }
  } catch {
    score += 5; reasons.push("Erreur analyse expéditeur");
  }

  /* --- 6) Indices structurels / densité --- */
  if (/\bform\b/i.test(body) || /<input\b/i.test(body)) {
    score += 8; reasons.push("Formulaire détecté dans l’email");
  }
  const plainLen = (body || "").trim().length;
  const linkCount = (links || []).length;
  if (plainLen < 120 && linkCount >= 1) {
    score += 6; reasons.push("Peu de texte mais présence de lien");
  }

  /* --- 7) Anti faux-positifs léger --- */
  if (linkCount > 0 && !isNaN(score)) {
    // tous les liens sont “trusted” et https → on baisse un peu
    const allHttps = (links || []).every(u => /^https:\/\//i.test(u));
    if (allHttps && linkList.length && linkList.every(u => trusted.has(baseDomain(getHostname(u))))) {
      score = Math.max(0, score - 8);
      reasons.push("Liens vers domaines officiels uniquement (atténuation)");
    }
  }

  // Nettoyage raisons + clamp
  const uniq = Array.from(new Set(reasons));
  return { score: Math.min(100, Math.round(score)), reasons: uniq };
}