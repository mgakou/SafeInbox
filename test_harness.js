import { analyzeEmail, loadRules } from './utils/local_scanner.js';

const THRESHOLD = 40;

const TESTS = [
  // ── PHISHING ÉVIDENTS ──────────────────────────────────
  {
    id: 1, label: "Phishing classique - urgence + credentials", category: "phishing",
    email: {
      subject: "URGENT : Votre compte a été suspendu",
      sender: "support@secure-update-paypal.xyz",
      senderName: "PayPal Security",
      body: "Cliquez ici immédiatement pour vérifier votre identité et votre mot de passe. Dernier avertissement.",
      links: ["https://secure-update-paypal.xyz/verify?token=abc", "https://bit.ly/xk29az"],
      attachments: [], anchors: []
    },
    expectedRange: [40, 100], expectedVerdict: "detected"
  },
  {
    id: 2, label: "Phishing bancaire - fausse Société Générale", category: "phishing",
    email: {
      subject: "Compte bloqué - vérifiez vos informations",
      sender: "alerte@societe-generale-secure.tk",
      senderName: "Société Générale",
      body: "Votre compte bancaire est bloqué suite à des activités suspectes. Remboursement en attente.",
      links: ["http://societe-generale-secure.tk/login", "http://tracking.tk/r?u=pay"],
      attachments: ["releve-compte.html"], anchors: []
    },
    expectedRange: [40, 100], expectedVerdict: "detected"
  },
  {
    id: 3, label: "Pièce jointe exécutable - facture piégée", category: "phishing",
    email: {
      subject: "Votre facture du mois",
      sender: "facturation@fournisseur-inconnu.com",
      senderName: "Service Facturation",
      body: "Veuillez trouver ci-joint votre facture. Merci de régler sous 48h.",
      links: [],
      attachments: ["facture_2025.exe", "document.js"], anchors: []
    },
    expectedRange: [20, 100], expectedVerdict: "detected"
  },
  {
    id: 4, label: "Lien vers IP directe + HTTP", category: "phishing",
    email: {
      subject: "Mise à jour requise",
      sender: "info@update-service.com",
      senderName: "Update Service",
      body: "Cliquez sur le lien pour mettre à jour votre logiciel de sécurité.",
      links: ["http://192.168.1.1/update", "http://203.0.113.42/login"],
      attachments: [], anchors: []
    },
    expectedRange: [20, 100], expectedVerdict: "detected"
  },
  {
    id: 5, label: "Spoofing Apple - domaine proche", category: "phishing",
    email: {
      subject: "Votre Apple ID a été compromis",
      sender: "noreply@apple-security-alert.com",
      senderName: "Apple",
      body: "Votre identifiant Apple a été utilisé depuis un appareil inconnu. Confirmez votre identité.",
      links: ["https://apple-security-alert.com/confirm"],
      attachments: [], anchors: []
    },
    expectedRange: [30, 100], expectedVerdict: "detected"
  },
  {
    id: 6, label: "Raccourcisseurs multiples + ton alarmiste", category: "phishing",
    email: {
      subject: "ACTION REQUISE IMMÉDIATEMENT !!!",
      sender: "noreply@notification-centre.top",
      senderName: "Centre de notification",
      body: "Votre accès expire dans 2 heures. Cliquez ici pour renouveler votre abonnement.",
      links: ["https://bit.ly/abc123", "https://tinyurl.com/def456", "https://rb.gy/ghi789"],
      attachments: [], anchors: []
    },
    expectedRange: [40, 100], expectedVerdict: "detected"
  },
  {
    id: 7, label: "Double extension suspecte", category: "phishing",
    email: {
      subject: "Document important",
      sender: "rh@entreprise-rh.com",
      senderName: "RH Entreprise",
      body: "Veuillez consulter le document en pièce jointe concernant votre contrat.",
      links: [],
      attachments: ["contrat.pdf.exe", "annexe.doc.js"], anchors: []
    },
    expectedRange: [20, 100], expectedVerdict: "detected"
  },
  {
    id: 8, label: "Sous-domaine profond + TLD risqué", category: "phishing",
    email: {
      subject: "Validation de votre compte",
      sender: "contact@mail.secure.login.verify.xyz",
      senderName: "Service Compte",
      body: "Merci de valider votre compte en cliquant sur le lien ci-dessous.",
      links: ["https://mail.secure.login.verify.xyz/confirm?id=1234"],
      attachments: [], anchors: []
    },
    expectedRange: [20, 100], expectedVerdict: "detected"
  },

  // ── EMAILS LÉGITIMES ───────────────────────────────────
  {
    id: 9, label: "Email amical banal", category: "legit",
    email: {
      subject: "On se voit ce week-end ?",
      sender: "ami@gmail.com",
      senderName: "Thomas",
      body: "Salut, tu es dispo samedi soir pour une pizza ? Dis-moi !",
      links: [], attachments: [], anchors: []
    },
    expectedRange: [0, 39], expectedVerdict: "clean"
  },
  {
    id: 10, label: "Newsletter marketing standard", category: "legit",
    email: {
      subject: "Découvrez nos nouveautés de printemps",
      sender: "newsletter@marque-mode.fr",
      senderName: "La Marque",
      body: "Bonjour, voici nos dernières collections disponibles sur notre site.",
      links: ["https://marque-mode.fr/collection-printemps", "https://marque-mode.fr/unsubscribe"],
      attachments: [], anchors: []
    },
    expectedRange: [0, 39], expectedVerdict: "clean"
  },
  {
    id: 11, label: "Email professionnel RH - contrat PDF", category: "legit",
    email: {
      subject: "Votre contrat de travail - à signer",
      sender: "rh@mon-entreprise.fr",
      senderName: "Service RH",
      body: "Bonjour, veuillez trouver ci-joint votre contrat pour signature. Bonne journée.",
      links: ["https://mon-entreprise.fr/signature/doc123"],
      attachments: ["contrat_2025.pdf"], anchors: []
    },
    expectedRange: [0, 39], expectedVerdict: "clean"
  },
  {
    id: 12, label: "Confirmation de commande Amazon HTTPS", category: "legit",
    email: {
      subject: "Votre commande a été expédiée",
      sender: "order-update@amazon.fr",
      senderName: "Amazon",
      body: "Votre commande #123-456 a été expédiée et sera livrée demain.",
      links: ["https://amazon.fr/orders/123-456", "https://amazon.fr/help"],
      attachments: [], anchors: []
    },
    expectedRange: [0, 39], expectedVerdict: "clean"
  },

  // ── CAS LIMITES (EDGE CASES) ───────────────────────────
  {
    id: 13, label: "Email vide - sans sujet ni corps", category: "edge",
    email: {
      subject: "", sender: "test@test.com", senderName: "",
      body: "", links: [], attachments: [], anchors: []
    },
    expectedRange: [0, 20], expectedVerdict: "clean"
  },
  {
    id: 14, label: "Beaucoup de mots-clés mais liens sains", category: "edge",
    email: {
      subject: "Mise à jour de sécurité importante",
      sender: "security@github.com",
      senderName: "GitHub Security",
      body: "Urgent : une mise à jour de sécurité est disponible. Vérifiez votre compte et confirmez votre identité.",
      links: ["https://github.com/security/advisories", "https://github.com/settings"],
      attachments: [], anchors: []
    },
    expectedRange: [0, 60], expectedVerdict: "fp_risk"
  },
  {
    id: 15, label: "PDF attaché + texte neutre", category: "fp",
    email: {
      subject: "Votre relevé de compte - Octobre 2025",
      sender: "releve@ma-banque-en-ligne.fr",
      senderName: "Ma Banque",
      body: "Bonjour, votre relevé de compte du mois d'octobre est disponible. Paiement reçu : 1 200€.",
      links: ["https://ma-banque-en-ligne.fr/releve/oct2025.pdf"],
      attachments: ["releve-octobre-2025.pdf"], anchors: []
    },
    expectedRange: [0, 50], expectedVerdict: "fp_risk"
  },
  {
    id: 16, label: "Expéditeur sans domaine (malformé)", category: "edge",
    email: {
      subject: "Test", sender: "sansdomaine", senderName: "Inconnu",
      body: "Test de l'analyse avec expéditeur malformé.",
      links: [], attachments: [], anchors: []
    },
    expectedRange: [0, 20], expectedVerdict: "clean"
  },
  {
    id: 17, label: "Score limite - pile à 40", category: "edge",
    email: {
      subject: "Vérifiez votre compte",
      sender: "info@service-legit.fr",
      senderName: "Service",
      body: "Veuillez vérifier votre compte pour continuer.",
      links: ["http://service-legit.fr/verify"],
      attachments: [], anchors: []
    },
    expectedRange: [5, 60], expectedVerdict: "fp_risk"
  },

  // ── FAUX POSITIFS POTENTIELS ───────────────────────────
  {
    id: 18, label: "Alerte sécu GitHub légitime", category: "fp",
    email: {
      subject: "Security alert: new sign-in to your account",
      sender: "no-reply@github.com",
      senderName: "GitHub",
      body: "We noticed a new sign-in to your account from a new device. If this was you, no action required. If not, please update your password immediately.",
      links: ["https://github.com/settings/security", "https://github.com/contact"],
      attachments: [], anchors: []
    },
    expectedRange: [0, 55], expectedVerdict: "fp_risk"
  },
  {
    id: 19, label: "Facture Stripe légitime", category: "fp",
    email: {
      subject: "Your invoice from Stripe",
      sender: "billing@stripe.com",
      senderName: "Stripe",
      body: "Here is your invoice for last month. Payment confirmed. Invoice #INV-2025-001.",
      links: ["https://stripe.com/invoice/inv001", "https://stripe.com/support"],
      attachments: ["invoice_stripe_oct2025.pdf"], anchors: []
    },
    expectedRange: [0, 40], expectedVerdict: "fp_risk"
  },
  {
  id: 20, label: "Mismatch ancre — texte PayPal, lien malveillant", category: "phishing",
  email: {
    subject: "Votre compte PayPal",
    sender: "support@mail-service.xyz",
    senderName: "PayPal",
    body: "Cliquez ci-dessous pour accéder à votre espace client.",
    links: ["http://steal-creds.xyz/paypal/login"],
    attachments: [],
    anchors: [
      // Cas 1 : texte affiche "paypal" mais lien ≠ domaine officiel
      { text: "Se connecter à PayPal", href: "http://steal-creds.xyz/paypal/login" },
      // Cas 2 : texte affiche une URL paypal.com mais href est différent
      { text: "https://paypal.com/secure", href: "http://steal-creds.xyz/paypal/login" }
    ]
  },
  expectedRange: [60, 100], expectedVerdict: "detected"
},
];

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────
let allResults = [];
let currentFilter = 'all';

function scoreClass(s) {
  if (s >= 70) return 'bad';
  if (s >= 40) return 'warn';
  return 'ok';
}

function verdictLabel(test, score) {
  const triggered = score >= THRESHOLD;
  if (test.expectedVerdict === 'detected') {
    return triggered
      ? `<span class="verdict pass">✓ DÉTECTÉ</span>`
      : `<span class="verdict fail">✗ MANQUÉ</span>`;
  }
  if (test.expectedVerdict === 'clean') {
    return triggered
      ? `<span class="verdict fail">⚠ FAUX POSITIF</span>`
      : `<span class="verdict pass">✓ PROPRE</span>`;
  }
  return triggered
    ? `<span class="verdict warn">⚠ À VÉRIFIER</span>`
    : `<span class="verdict warn">~ LIMITE</span>`;
}

function renderResults(results, filter) {
  const tbody = document.getElementById('resultsBody');
  const filtered = filter === 'all' ? results : results.filter(r => r.test.category === filter);

  if (!filtered.length) {
    tbody.innerHTML = `<tr class="loading-row"><td colspan="6">Aucun résultat pour ce filtre.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(r => {
    const sc = scoreClass(r.score);
    const inRange = r.score >= r.test.expectedRange[0] && r.score <= r.test.expectedRange[1];
    const reasonsHtml = r.reasons.length
      ? r.reasons.map(reason => `<span class="reason-chip flagged">${reason}</span>`).join('')
      : `<span class="reason-chip">—</span>`;

    return `<tr data-category="${r.test.category}">
      <td class="mono" style="color:var(--muted)">${r.test.id}</td>
      <td>
        <div class="case-name">${r.test.label}</div>
        <div class="case-meta">${r.test.category} · seuil: ${THRESHOLD}</div>
      </td>
      <td>
        <span class="score-pill ${sc}">${r.score}/100</span>
        ${!inRange ? `<div style="font-size:10px;color:var(--muted);font-family:var(--mono);margin-top:4px">attendu: [${r.test.expectedRange[0]}-${r.test.expectedRange[1]}]</div>` : ''}
      </td>
      <td><span class="verdict ${r.test.expectedVerdict === 'detected' ? 'fail' : r.test.expectedVerdict === 'clean' ? 'pass' : 'warn'}" style="opacity:.6">${r.test.expectedVerdict}</span></td>
      <td><div class="reasons-list">${reasonsHtml}</div></td>
      <td>${verdictLabel(r.test, r.score)}</td>
    </tr>`;
  }).join('');
}

function updateStats(results) {
  document.getElementById('statTotal').textContent = results.length;
  document.getElementById('statDetected').textContent =
    `${results.filter(r => r.test.expectedVerdict === 'detected' && r.score >= THRESHOLD).length}/${results.filter(r => r.test.expectedVerdict === 'detected').length}`;
  document.getElementById('statOk').textContent =
    `${results.filter(r => r.test.expectedVerdict === 'clean' && r.score < THRESHOLD).length}/${results.filter(r => r.test.expectedVerdict === 'clean').length}`;
  document.getElementById('statFp').textContent =
    results.filter(r => r.test.expectedVerdict === 'clean' && r.score >= THRESHOLD).length;
}

// ─────────────────────────────────────────────
// Run all tests
// ─────────────────────────────────────────────
async function runAllTests() {
  const btn = document.getElementById('runAllBtn');
  const progressBar = document.getElementById('progressBar');
  const progressFill = document.getElementById('progressFill');

  btn.disabled = true;
  btn.textContent = '⏳ Analyse en cours…';
  progressBar.classList.add('active');
  allResults = [];

  document.getElementById('resultsBody').innerHTML =
    `<tr class="loading-row"><td colspan="6">Chargement des règles…</td></tr>`;

  try {
    await loadRules();
  } catch (e) {
    document.getElementById('resultsBody').innerHTML =
      `<tr class="loading-row"><td colspan="6" style="color:var(--bad)">❌ Erreur chargement règles : ${e.message}</td></tr>`;
    btn.disabled = false;
    btn.textContent = '▶ Lancer tous les tests';
    progressBar.classList.remove('active');
    return;
  }

  for (let i = 0; i < TESTS.length; i++) {
    const test = TESTS[i];
    progressFill.style.width = `${Math.round(((i + 1) / TESTS.length) * 100)}%`;
    try {
      const result = await analyzeEmail(test.email);
      allResults.push({ test, score: result.score, reasons: result.reasons });
    } catch (e) {
      allResults.push({ test, score: -1, reasons: [`Erreur: ${e.message}`] });
    }
    renderResults(allResults, currentFilter);
    updateStats(allResults);
    await new Promise(r => setTimeout(r, 10));
  }

  btn.disabled = false;
  btn.textContent = '↺ Relancer les tests';
  setTimeout(() => progressBar.classList.remove('active'), 600);
}

// ─────────────────────────────────────────────
// Test manuel
// ─────────────────────────────────────────────
async function runManual() {
  const email = {
    subject: document.getElementById('m-subject').value,
    sender: document.getElementById('m-sender').value,
    senderName: document.getElementById('m-senderName').value,
    body: document.getElementById('m-body').value,
    links: document.getElementById('m-links').value.split('\n').map(l => l.trim()).filter(Boolean),
    attachments: document.getElementById('m-attachments').value.split('\n').map(a => a.trim()).filter(Boolean),
    anchors: []
  };

  const resultEl = document.getElementById('manualResult');
  resultEl.classList.remove('show');
  resultEl.textContent = 'Analyse…';
  resultEl.classList.add('show');

  try {
    await loadRules();
    const { score, reasons } = await analyzeEmail(email);
    const sc = scoreClass(score);
    const triggered = score >= THRESHOLD;

    resultEl.innerHTML = `
      <div class="score-line" style="color:var(--${sc})">Score : ${score}/100
        <span style="font-size:14px;margin-left:12px">${triggered ? '⚠️ SUSPECT (≥ seuil ' + THRESHOLD + ')' : '✅ Sous le seuil (' + THRESHOLD + ')'}</span>
      </div>
      <div style="color:var(--muted);font-size:12px;margin-bottom:10px">${reasons.length} raison(s) détectée(s)</div>
      <div class="reasons-list">
        ${reasons.length
          ? reasons.map(r => `<span class="reason-chip flagged">${r}</span>`).join('')
          : '<span class="reason-chip">Aucune raison détectée</span>'
        }
      </div>`;
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--bad)">Erreur : ${e.message}</span>`;
  }
}

// ─────────────────────────────────────────────
// Init event listeners
// ─────────────────────────────────────────────
document.getElementById('runAllBtn').addEventListener('click', runAllTests);
document.getElementById('runManualBtn').addEventListener('click', runManual);

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const target = tab.dataset.tab;
    document.getElementById('suitePanel').classList.toggle('hidden', target !== 'suite');
    document.getElementById('manualPanel').classList.toggle('active', target === 'manual');
  });
});

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
    if (allResults.length) renderResults(allResults, currentFilter);
  });
});
