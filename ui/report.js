// ================================================================
// report.js — Page de rapport d'analyse SafeInbox
// Lit les données depuis chrome.storage.session et les affiche
// ================================================================

// ── Helpers ──────────────────────────────────────────────────────

function getHostname(u = '') {
  try { return new URL(u).hostname.toLowerCase(); } catch { return ''; }
}

function formatDate(iso = '') {
  if (!iso) return '—';
  try {
    return new Intl.DateTimeFormat('fr-FR', {
      day: '2-digit', month: 'long', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    }).format(new Date(iso));
  } catch { return iso; }
}

function escHtml(str = '') {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Severity classification ───────────────────────────────────────

function classifyReason(reason = '') {
  const t = reason.toLowerCase();

  if (
    t.includes('ancre trompeuse') ||
    t.includes('url affich') ||
    t.includes('lien vers ip') ||
    t.includes('pièce jointe risquée') ||
    t.includes('double extension') ||
    t.includes('data:') ||
    t.includes('homoglyphe')
  ) return 'critical';

  if (
    t.includes('raccourcisseur') ||
    t.includes('marque') ||
    t.includes('tld risqué') ||
    t.includes('nom affiche') ||
    t.includes('sous-domaine') ||
    t.includes('hameçonnage') ||
    t.includes('entropie') ||
    t.includes('expéditeur non analysable')
  ) return 'high';

  return 'medium';
}

const REASON_ICONS = {
  critical: '🔴',
  high:     '🟠',
  medium:   '🟡',
};

const REASON_LABELS = {
  critical: 'Critique',
  high:     'Suspect',
  medium:   'Attention',
};

// ── Link analysis ─────────────────────────────────────────────────

const SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','is.gd','cutt.ly',
  'rebrand.ly','rb.gy','lnkd.in','goo.gl','ow.ly'
]);

function analyzeLinkFlags(url = '') {
  const flags = [];
  const host = getHostname(url);

  if (/^http:\/\//i.test(url))   flags.push({ label: 'HTTP', level: 'warn' });
  if (/^data:/i.test(url))        flags.push({ label: 'data:', level: 'danger' });
  if (SHORTENERS.has(host))       flags.push({ label: 'Raccourcisseur', level: 'danger' });
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) flags.push({ label: 'IP directe', level: 'danger' });

  const tld = host.split('.').pop();
  const riskyTLDs = ['zip','mov','xyz','top','gq','tk','ml','ga','cf','click','work','shop'];
  if (riskyTLDs.includes(tld))    flags.push({ label: `.${tld}`, level: 'warn' });

  const path = (() => { try { return new URL(url).pathname.toLowerCase(); } catch { return ''; } })();
  if (/(login|signin|verify|update|password|reset|secure|confirm)/.test(path)) {
    flags.push({ label: 'Chemin phishing', level: 'warn' });
  }

  return flags;
}

function linkDangerLevel(flags = []) {
  if (flags.some(f => f.level === 'danger')) return 'danger';
  if (flags.some(f => f.level === 'warn'))   return 'warn';
  return 'safe';
}

// ── Severity config ───────────────────────────────────────────────

function getSevConfig(score) {
  if (score >= 70) return {
    key: 'critical',
    label: 'Critique',
    desc: 'Phishing très probable — ne pas interagir avec cet email.',
    color: 'var(--critical)',
    bg: 'var(--critical-bg)',
  };
  if (score >= 40) return {
    key: 'high',
    label: 'Suspect',
    desc: 'Signaux suspects détectés — prudence recommandée.',
    color: 'var(--high)',
    bg: 'var(--high-bg)',
  };
  if (score >= 15) return {
    key: 'medium',
    label: 'Attention',
    desc: 'Quelques signaux faibles — vérification conseillée.',
    color: 'var(--medium)',
    bg: 'var(--medium-bg)',
  };
  return {
    key: 'ok',
    label: 'Sûr',
    desc: 'Aucun signal suspect détecté.',
    color: 'var(--ok)',
    bg: 'var(--ok-bg)',
  };
}

// ── Render ────────────────────────────────────────────────────────

function render(data) {
  const { score = 0, reasons = [], email = {}, timestamp = '' } = data;
  const sev = getSevConfig(score);

  // Score ring
  const R = 44;
  const C = 2 * Math.PI * R;
  const offset = C * (1 - Math.min(score, 100) / 100);

  // Group reasons by severity
  const grouped = { critical: [], high: [], medium: [] };
  for (const r of reasons) {
    const level = classifyReason(r);
    grouped[level].push(r);
  }

  // Breakdown bar widths
  const critPct = reasons.length ? Math.round((grouped.critical.length / reasons.length) * 100) : 0;
  const highPct = reasons.length ? Math.round((grouped.high.length / reasons.length) * 100) : 0;
  const medPct  = reasons.length ? 100 - critPct - highPct : 0;

  // Render reasons groups
  function renderGroup(level, items) {
    if (!items.length) return '';
    return `
      <div class="reason-group">
        <div class="reason-group-label" style="color:var(--${level === 'critical' ? 'critical' : level === 'high' ? 'high' : 'medium'})">
          ${REASON_ICONS[level]} ${REASON_LABELS[level]} · ${items.length} signal${items.length > 1 ? 's' : ''}
        </div>
        ${items.map((r, i) => `
          <div class="reason-item ${level}" style="animation-delay:${i * 40}ms">
            <span class="reason-icon">${REASON_ICONS[level]}</span>
            <span class="reason-text">${escHtml(r)}</span>
          </div>
        `).join('')}
      </div>`;
  }

  // Render links
  const links = Array.isArray(email.links) ? email.links : [];
  const linksHtml = links.length
    ? `<div class="links-list">
        ${links.map(url => {
          const flags = analyzeLinkFlags(url);
          const level = linkDangerLevel(flags);
          return `
            <div class="link-item">
              <div class="link-status ${level}"></div>
              <div style="flex:1">
                <div class="link-url">${escHtml(url)}</div>
                ${flags.length ? `<div class="link-flags">
                  ${flags.map(f => `<span class="link-flag ${f.level}">${escHtml(f.label)}</span>`).join('')}
                </div>` : ''}
              </div>
            </div>`;
        }).join('')}
      </div>`
    : '<div class="empty">Aucun lien détecté dans cet email</div>';

  // Render attachments
  const attachments = Array.isArray(email.attachments) ? email.attachments : [];

  const totalReasons = grouped.critical.length + grouped.high.length + grouped.medium.length;

  document.getElementById('app').innerHTML = `
    <div class="page">

      <!-- Header -->
      <header class="header">
        <div class="header-left">
          <div class="breadcrumb">SafeInbox <span>›</span> Rapport d'analyse</div>
          <h1>Analyse <em>${sev.label.toLowerCase()}</em><br>détectée</h1>
          <div class="meta-line">
            <span>${formatDate(timestamp)}</span>
            <span class="sep">·</span>
            <span>${totalReasons} signal${totalReasons > 1 ? 's' : ''} détecté${totalReasons > 1 ? 's' : ''}</span>
            <span class="sep">·</span>
            <span>Analyse locale</span>
          </div>
        </div>
      </header>

      <!-- Score hero -->
      <div class="score-hero" style="--sev-color:${sev.color}; --sev-bg:${sev.bg}">
        <div class="ring-wrap">
          <svg class="ring-svg" width="100" height="100" viewBox="0 0 100 100">
            <circle class="ring-bg" cx="50" cy="50" r="${R}" fill="none" stroke-width="6"/>
            <circle class="ring-val" cx="50" cy="50" r="${R}" fill="none" stroke-width="6"
              stroke-dasharray="${C}"
              stroke-dashoffset="${offset}"
              style="stroke:${sev.color}"/>
          </svg>
          <div class="ring-num">
            <span class="num">${score}</span>
            <span class="denom">/100</span>
          </div>
        </div>
        <div class="score-info">
          <div class="sev-badge" style="--sev-color:${sev.color}; --sev-bg:${sev.bg}; border-color:${sev.color}; color:${sev.color}; background:${sev.bg}">
            ${sev.label}
          </div>
          <div class="score-label">${sev.desc}</div>
          <div class="score-sub">Seuil d'alerte : 40 · Score brut : ${score}/100</div>
          ${reasons.length ? `
            <div class="breakdown">
              ${critPct ? `<div class="breakdown-seg" style="width:${critPct}%;background:var(--critical)"></div>` : ''}
              ${highPct ? `<div class="breakdown-seg" style="width:${highPct}%;background:var(--high)"></div>` : ''}
              ${medPct  ? `<div class="breakdown-seg" style="width:${medPct}%;background:var(--medium)"></div>` : ''}
            </div>` : ''}
        </div>
      </div>

      <!-- Deep scan placeholder -->
      <div class="deep-scan-banner">
        <div class="deep-scan-text">
          <strong>Analyse approfondie (IA)</strong>
          Détection sémantique avancée — disponible prochainement.
        </div>
        <button class="deep-scan-btn" disabled>Bientôt disponible</button>
      </div>

      <!-- Email metadata -->
      <div class="email-card">
        <div class="card-title">Informations sur l'email</div>
        <div class="email-row">
          <span class="email-key">Expéditeur</span>
          <span class="email-val">${escHtml(email.sender || '—')}</span>
        </div>
        <div class="email-row">
          <span class="email-key">Nom affiché</span>
          <span class="email-val">${escHtml(email.senderName || '—')}</span>
        </div>
        <div class="email-row">
          <span class="email-key">Sujet</span>
          <span class="email-val">${escHtml(email.subject || '—')}</span>
        </div>
        <div class="email-row">
          <span class="email-key">Liens</span>
          <span class="email-val">${links.length} lien${links.length > 1 ? 's' : ''}</span>
        </div>
        <div class="email-row">
          <span class="email-key">Pièces jointes</span>
          <span class="email-val">${attachments.length ? escHtml(attachments.join(', ')) : 'Aucune'}</span>
        </div>
      </div>

      <!-- Reasons -->
      <div class="section">
        <div class="section-header">
          <div class="section-title">Signaux détectés</div>
          <div class="section-count">${totalReasons}</div>
          <div class="section-line"></div>
        </div>
        ${totalReasons === 0
          ? '<div class="empty">Aucun signal suspect détecté</div>'
          : `
            ${renderGroup('critical', grouped.critical)}
            ${renderGroup('high',     grouped.high)}
            ${renderGroup('medium',   grouped.medium)}
          `
        }
      </div>

      <!-- Links -->
      <div class="section">
        <div class="section-header">
          <div class="section-title">Liens analysés</div>
          <div class="section-count">${links.length}</div>
          <div class="section-line"></div>
        </div>
        ${linksHtml}
      </div>

      <!-- Footer -->
      <footer class="footer">
        <div class="footer-logo">
          <div class="footer-dot"></div>
          SafeInbox · Analyse 100% locale
        </div>
        <div>${formatDate(timestamp)}</div>
      </footer>

    </div>`;
}

function renderError(msg = '') {
  document.getElementById('app').innerHTML = `
    <div class="state-screen">
      <div class="state-icon">⚠️</div>
      <div style="color:var(--fg)">${escHtml(msg)}</div>
      <div style="color:var(--muted);font-size:11px">Ouvre ce rapport depuis le banner SafeInbox sur Gmail.</div>
    </div>`;
}

// ── Bootstrap ─────────────────────────────────────────────────────

(async () => {
  try {
    const result = await chrome.storage.local.get('safeInboxReport');
    const data = result?.safeInboxReport;

    if (!data) {
      renderError('Aucune donnée de rapport disponible.');
      return;
    }

    render(data);
  } catch (err) {
    renderError(`Erreur de chargement : ${err.message}`);
  }
})();
