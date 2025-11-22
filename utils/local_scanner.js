// ================================================================
// utils/local_scanner.js — moteur local basé sur un fichier JSON externe
// Analyse complète + analyse légère (trusted senders)
// ================================================================

let RULES = null;

/* ======================== Chargement des règles ======================== */
export async function loadRules() {
  if (RULES) return RULES; // cache
  const res = await fetch(chrome.runtime.getURL("utils/rules.json"));
  RULES = await res.json();
  console.log("[SafeInbox] Règles chargées :", RULES);
  return RULES;
}

/* ======================== Helpers ======================== */
const MIX_CYRILLIC = /[\u0400-\u04FF]/;
const MIX_GREEK    = /[\u0370-\u03FF]/;
const SLD_EXCEPTIONS = new Set(["co.uk","ac.uk","gov.uk","com.au","com.br","com.mx"]);

function normalize(t=""){return t.normalize("NFD").replace(/\p{Diacritic}/gu,"").toLowerCase();}
function getHostname(u=""){try{return new URL(u).hostname.toLowerCase();}catch{return"";}}
function baseDomain(h=""){
  const p=h.split(".").filter(Boolean);
  if(p.length<2)return h;
  const lastTwo=p.slice(-2).join(".");
  return SLD_EXCEPTIONS.has(lastTwo)&&p.length>=3?p.slice(-3).join("."):lastTwo;
}
function lev(a="",b=""){if(a===b)return 0;if(!a.length)return b.length;if(!b.length)return a.length;
  const dp=new Array(b.length+1).fill(0).map((_,i)=>i);
  for(let i=1;i<=a.length;i++){let prev=i-1,cur=i;
    for(let j=1;j<=b.length;j++){const tmp=dp[j];
      dp[j]=Math.min(dp[j]+1,cur+1,prev+(a[i-1]===b[j-1]?0:1));
      prev=tmp;cur=dp[j];
    }}
  return dp[b.length];
}

// ✅ sécurisation : vérifier que RULES est chargé avant utilisation
function hasDoubleExtension(n=""){
  if (!RULES || !RULES.attachments) return false;
  const p=n.toLowerCase().split(".");
  if (p.length < 3) return false;
  return RULES.attachments.dangerous.includes(p.pop());
}

function isIPAddress(h=""){return /^(\d{1,3}\.){3}\d{1,3}$/.test(h)||/^[a-f0-9:]+$/i.test(h);}
function subdomainDepth(h=""){return Math.max(0,h.split(".").filter(Boolean).length-2);}
function manyExclamations(t=""){return (t.match(/!/g)||[]).length>=3;}
function allCapsRatio(t=""){const w=t.split(/\s+/).filter(x=>x.length>=3);
  const caps=w.filter(x=>/^[A-ZÀÂÄÇÉÈÊËÏÎÔÖÙÛÜŸ-]+$/.test(x)).length;
  return w.length?caps/w.length:0;}
function pathLooksPhishy(u=""){try{
  const p=(new URL(u).pathname+" "+new URL(u).search).toLowerCase();
  return /(login|signin|verify|update|password|reset|secure|confirm)/.test(p);
}catch{return false;}}

/* ======================== Analyse complète ======================== */
export async function analyzeEmail({ subject="", sender="", body="", links=[], attachments=[], anchors=[], senderName="" }) {
  const rules = await loadRules(); // 🔸 s'assure que RULES est rempli
  let score = 0;
  const reasons = [];

  const text = normalize(`${subject} ${body}`);
  const subj = normalize(subject);
  const sndr = (sender || "").toLowerCase();

  // --- 1) Analyse du contenu texte ---
  for (const word of rules.keywords.risky) {
    if (text.includes(word)) { score += 5; reasons.push(`Mot clé suspect : "${word}"`); }
  }
  if (manyExclamations(subject)||manyExclamations(body)) {score+=4;reasons.push("Ponctuation alarmiste");}
  if (allCapsRatio(subject)>0.4){score+=4;reasons.push("Sujet en majuscules");}

  // --- 2) Liens et domaines ---
  for (const url of links) {
    const host = getHostname(url);
    const base = baseDomain(host);
    const tld  = host.split(".").pop();

    if (rules.urls.shorteners.includes(host)) {score+=8;reasons.push(`Raccourcisseur : ${host}`);}
    if (rules.urls.riskyTLD.includes(tld))   {score+=6;reasons.push(`TLD risqué : .${tld}`);}
    if (isIPAddress(host))                   {score+=10;reasons.push(`Lien vers IP : ${host}`);}
    if (/^http:\/\//i.test(url))             {score+=3;reasons.push("Lien non sécurisé (HTTP)");}
    if (/^data:/i.test(url))                 {score+=10;reasons.push("Lien data: potentiellement obfusqué");}
    if (subdomainDepth(host)>=3)             {score+=4;reasons.push(`Sous-domaine profond : ${host}`);}
    if (pathLooksPhishy(url))                {score+=6;reasons.push("Chemin typique d’hameçonnage");}

    const brandsMentioned = Object.keys(rules.brands).filter(b=>text.includes(b));
    for(const b of brandsMentioned){
      const officiels = rules.brands[b].map(d=>baseDomain(d));
      const proche = officiels.some(d=>d===base||lev(d,base)<=2);
      if(!proche){score+=10;reasons.push(`Marque "${b}" citée mais domaine = ${base}`);}
    }
  }

  // --- 3) Pièces jointes ---
  for (const file of attachments) {
    const ext = (file.split(".").pop() || "").toLowerCase();
    if (rules.attachments.dangerous.includes(ext)) {
      score += 12; reasons.push(`Pièce jointe risquée : ${file}`);
    }
    if (hasDoubleExtension(file)) {
      score += 10; reasons.push(`Double extension suspecte : ${file}`);
    }
  }

  // --- 4) Expéditeur ---
  try {
    const domain = sndr.split("@")[1];
    if (!domain) {score+=5;reasons.push("Expéditeur non analysable");}
    const brandMentioned = Object.keys(rules.brands).find(b=>senderName?.toLowerCase().includes(b));
    if (brandMentioned) {
      const bd = baseDomain(domain);
      const officiels = rules.brands[brandMentioned].map(d=>baseDomain(d));
      if (!officiels.includes(bd)) {
        score += 10;
        reasons.push(`Nom affiche ${brandMentioned} mais domaine = ${bd}`);
      }
    }
  } catch {score+=3;}

  // --- 5) Anti faux positifs ---
  const trusted = new Set(rules.trusted);
  const allHttps = links.every(u => /^https:\/\//i.test(u));
  if (links.length && allHttps && links.every(u => trusted.has(baseDomain(getHostname(u))))) {
    score = Math.max(0, score - 8);
    reasons.push("Liens vers domaines officiels (atténuation)");
  }

  return { score: Math.min(100, Math.round(score)), reasons: Array.from(new Set(reasons)) };
}

/* ======================== Analyse légère (trusted senders) ======================== */
/**
 * Analyse rapide et partielle utilisée pour les expéditeurs de confiance.
 * Objectif : détecter les signaux évidents sans appliquer toutes les règles.
 */
export async function lightCheckEmail({ body = "", links = [], attachments = [] }) {
  let score = 0;
  const reasons = [];

  // 🔹 Vérification des liens
  for (const url of links) {
    if (!/^https:\/\//i.test(url)) {
      score += 10;
      reasons.push("Lien non sécurisé (HTTP)");
    }
    if (/bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rebrand\.ly|rb\.gy|lnkd\.in|goo\.gl|ow\.ly/i.test(url)) {
      score += 8;
      reasons.push("Raccourcisseur d’URL détecté");
    }
    if (/\.(zip|rar|7z|exe|scr|bat|cmd|ps1|apk|iso|img|docm|xlsm|pptm)([\/?#:]|$)/i.test(url)) {
      score += 10;
      reasons.push("Lien vers un fichier potentiellement exécutable");
    }
  }

  // 🔹 Vérification du contenu du corps
  if (/\b(mot de passe|password|identifiant|login|vérifiez|verify)\b/i.test(body)) {
    score += 8;
    reasons.push("Demande d'identifiants détectée");
  }
  if (/\burgent|urgence|immédiatement|immediatement|sans délai|asap\b/i.test(body)) {
    score += 6;
    reasons.push("Ton pressant ou urgence détecté");
  }

  // 🔹 Vérification des pièces jointes
  for (const file of attachments) {
    const lower = (file || "").toLowerCase();
    if (/\.(exe|js|vbs|scr|bat|cmd|ps1|apk|zip|rar|7z|iso|img|docm|xlsm|pptm)$/i.test(lower)) {
      score += 20;
      reasons.push(`Pièce jointe potentiellement dangereuse : ${file}`);
    }
  }

  // 🔹 Nettoyage / sortie
  return {
    score: Math.min(100, Math.round(score)),
    reasons: Array.from(new Set(reasons))
  };
}