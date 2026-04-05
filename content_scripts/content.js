// ==========================================================
// 🛡️ SafeInbox – Content Script (Gmail)
// Full local scan for every email (except ignored senders)
// ==========================================================

(async () => {
  const DEFAULT_THRESHOLD = 40;
  const GMAIL_MAIN_SELECTOR = 'div[role="main"]';
  const SUBJECT_SELECTOR = 'h2.hP';
  const SENDER_SELECTOR = '.gD';
  const SENDER_NAME_SELECTOR = '.gD';
  const BODY_SELECTOR = '.a3s';
  const LINK_SELECTOR = '.a3s a';
  const ATTACHMENT_SELECTOR = '[download_url]';
  const BANNER_IFRAME_ID = 'anti-phish-banner';
  const BANNER_SELECTOR = `#${BANNER_IFRAME_ID}`;

  const state = {
    threshold: DEFAULT_THRESHOLD,
    lastEmailHash: '',
    currentViewId: null,
    lastEmailData: null,
    highlighted: false,
    highlightedNodes: [],
    isAlive: true,
    analyzing: false,
    observer: null,
    logger: null,
    analyzeEmailFn: null,
  };

  const shortenerRegex = /(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rebrand\.ly|rb\.gy|lnkd\.in|goo\.gl|ow\.ly)/i;

  function isContextInvalidatedError(err) {
    const msg = String(err?.message || err || '').toLowerCase();
    return (
      msg.includes('extension context invalidated') ||
      msg.includes('context invalidated') ||
      msg.includes('extension has been invalidated')
    );
  }

  function isContextAlive() {
    try {
      return state.isAlive && Boolean(chrome?.runtime?.id);
    } catch {
      return false;
    }
  }

  function stopContext(reason = 'unknown') {
    if (!state.isAlive) return;
    state.isAlive = false;
    try {
      state.observer?.disconnect();
    } catch {}
    removeBanner();
    clearHighlights();
    console.warn(`[SafeInbox] Context stopped (${reason})`);
  }

  function debounce(fn, delay) {
    let timer = null;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  }

  function safeCall(fn, fallback = null) {
    try {
      return fn();
    } catch {
      return fallback;
    }
  }

  function wait(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function safeStorageSyncGet(defaults) {
    if (!isContextAlive()) return defaults;
    try {
      return await new Promise((resolve, reject) => {
        chrome.storage.sync.get(defaults, (result) => {
          const lastError = chrome.runtime?.lastError;
          if (lastError) {
            reject(new Error(lastError.message));
            return;
          }
          resolve(result || defaults);
        });
      });
    } catch (err) {
      if (isContextInvalidatedError(err)) stopContext('storage-sync-get invalidated');
      return defaults;
    }
  }

  async function safeStorageSyncSet(values) {
    if (!isContextAlive()) return false;
    try {
      await new Promise((resolve, reject) => {
        chrome.storage.sync.set(values, () => {
          const lastError = chrome.runtime?.lastError;
          if (lastError) {
            reject(new Error(lastError.message));
            return;
          }
          resolve();
        });
      });
      return true;
    } catch (err) {
      if (isContextInvalidatedError(err)) stopContext('storage-sync-set invalidated');
      return false;
    }
  }

  function normalizeUrl(raw = '') {
    try {
      const u = new URL(raw);
      return `${u.origin}${u.pathname}${u.hash || ''}`;
    } catch {
      return raw || '';
    }
  }

  function simpleHash(input = '') {
    let h = 5381;
    for (let i = 0; i < input.length; i += 1) {
      h = (h * 33) ^ input.charCodeAt(i);
    }
    return (h >>> 0).toString(36);
  }

  function buildEmailHash(emailData) {
    const subject = (emailData?.subject || '').trim();
    const sender = (emailData?.sender || '').toLowerCase().trim();
    const body = (emailData?.body || '').trim();
    const links = Array.isArray(emailData?.links) ? emailData.links.join('|') : '';
    const attachments = Array.isArray(emailData?.attachments) ? emailData.attachments.join('|') : '';
    const url = normalizeUrl(window.location.href);
    const key = [
      sender,
      subject,
      body.length,
      body.slice(0, 240),
      links,
      attachments,
      url,
    ].join('||');
    return `mail_${simpleHash(key)}`;
  }

  async function loadThreshold() {
    const { threshold } = await safeStorageSyncGet({ threshold: DEFAULT_THRESHOLD });
    state.threshold = Number.isFinite(Number(threshold)) ? Number(threshold) : DEFAULT_THRESHOLD;
  }

  async function getIgnoredSenders() {
    const { ignoredSenders = [] } = await safeStorageSyncGet({ ignoredSenders: [] });
    return Array.isArray(ignoredSenders) ? ignoredSenders.map((x) => String(x || '').toLowerCase()) : [];
  }

  async function isSenderIgnored(senderEmail) {
    const normalized = String(senderEmail || '').toLowerCase().trim();
    if (!normalized) return false;
    const ignored = await getIgnoredSenders();
    return ignored.includes(normalized);
  }

  async function addIgnoredSender(senderEmail) {
    const email = String(senderEmail || '').toLowerCase().trim();
    if (!email || !email.includes('@')) return false;
    const ignored = await getIgnoredSenders();
    const merged = Array.from(new Set([...ignored, email]));
    return safeStorageSyncSet({ ignoredSenders: merged });
  }

  function extractEmailData() {
    try {
      const subject = safeCall(() => document.querySelector(SUBJECT_SELECTOR)?.innerText, '') || '';
      const senderEl = document.querySelector(SENDER_SELECTOR);
      const sender = senderEl?.getAttribute('email') || '';
      const senderName = safeCall(() => document.querySelector(SENDER_NAME_SELECTOR)?.textContent?.trim(), '') || '';
      const body = safeCall(() => document.querySelector(BODY_SELECTOR)?.innerText, '') || '';

      const linkNodes = Array.from(document.querySelectorAll(LINK_SELECTOR));
      const links = linkNodes.map((a) => a.href).filter(Boolean);
      const anchors = linkNodes.map((a) => ({ href: a.href || '', text: a.textContent || '' }));

      const attachmentNodes = Array.from(document.querySelectorAll(ATTACHMENT_SELECTOR));
      const attachments = attachmentNodes
        .map((el) => el.getAttribute('download_url')?.split(':').pop() || '')
        .filter(Boolean);

      if (!subject && !body) return null;
      return { subject, sender, senderName, body, links, attachments, anchors };
    } catch (err) {
      console.warn('[SafeInbox] Email extraction failed:', err);
      return null;
    }
  }

  function ensureBanner() {
    let iframe = document.getElementById(BANNER_IFRAME_ID);
    if (iframe) return iframe;

    iframe = document.createElement('iframe');
    iframe.id = BANNER_IFRAME_ID;
    iframe.src = chrome.runtime.getURL('ui/warning_banner.html');
    iframe.style.cssText = [
      'position: fixed',
      'right: 12px',
      'bottom: 12px',
      'width: 320px',
      'height: 56px',
      'border: 0',
      'background: transparent',
      'z-index: 2147483647',
      'pointer-events: auto',
    ].join(';');
    document.body.appendChild(iframe);
    return iframe;
  }

  function getBannerFrame() {
    return document.getElementById(BANNER_IFRAME_ID);
  }

  function postBannerData(scoreDetails, emailData) {
    const iframe = ensureBanner();
    const payload = {
      score: Number(scoreDetails?.score || 0),
      reasons: Array.isArray(scoreDetails?.reasons) ? scoreDetails.reasons : [],
      sender: emailData?.sender || '',
    };
  
    const send = () => {
      try {
        iframe.contentWindow?.postMessage(payload, '*');
      } catch {}
    };
  
    // Si le banner a déjà été chargé une fois, on envoie directement
    if (iframe.dataset.bannerReady === 'true') {
      send();
    } else {
      // Première apparition : attendre le load complet, puis laisser
      // 50ms pour que le JS du banner enregistre ses event listeners
      iframe.addEventListener('load', () => {
        iframe.dataset.bannerReady = 'true';
        setTimeout(send, 50);
      }, { once: true });
    }
  }

  function removeBanner() {
    safeCall(() => document.querySelector(BANNER_SELECTOR)?.remove());
  }

  function clearHighlights() {
    if (!state.highlightedNodes.length) {
      state.highlighted = false;
      return;
    }
    for (const item of state.highlightedNodes) {
      if (!item?.el?.isConnected) continue;
      item.el.style.outline = item.prevOutline || '';
      item.el.style.backgroundColor = item.prevBg || '';
      item.el.style.borderRadius = item.prevRadius || '';
    }
    state.highlightedNodes = [];
    state.highlighted = false;
  }

  function isSuspiciousLink(url = '') {
    if (!url) return false;
    return /^http:\/\//i.test(url) || shortenerRegex.test(url);
  }

  function applyHighlights(emailData) {
    clearHighlights();
    const linkNodes = Array.from(document.querySelectorAll(LINK_SELECTOR));
    const attachmentNodes = Array.from(document.querySelectorAll(ATTACHMENT_SELECTOR));

    for (const linkEl of linkNodes) {
      if (!isSuspiciousLink(linkEl.href || '')) continue;
      state.highlightedNodes.push({
        el: linkEl,
        prevOutline: linkEl.style.outline,
        prevBg: linkEl.style.backgroundColor,
        prevRadius: linkEl.style.borderRadius,
      });
      linkEl.style.outline = '2px solid rgba(229,57,53,0.95)';
      linkEl.style.backgroundColor = 'rgba(229,57,53,0.15)';
      linkEl.style.borderRadius = '4px';
    }

    for (const node of attachmentNodes) {
      state.highlightedNodes.push({
        el: node,
        prevOutline: node.style.outline,
        prevBg: node.style.backgroundColor,
        prevRadius: node.style.borderRadius,
      });
      node.style.outline = '2px solid rgba(243,156,18,0.95)';
      node.style.backgroundColor = 'rgba(243,156,18,0.15)';
      node.style.borderRadius = '4px';
    }

    state.highlighted = true;
    if (!emailData?.links?.length && !emailData?.attachments?.length) clearHighlights();
  }

  function toggleHighlights() {
    if (!state.lastEmailData) return;
    if (state.highlighted) clearHighlights();
    else applyHighlights(state.lastEmailData);
  }

  async function maybeLoadLogger() {
    try {
      const mod = await import(chrome.runtime.getURL('utils/logger.js'));
      if (mod?.upsertAnalysisLog && mod?.appendUserAction) {
        state.logger = {
          upsertAnalysisLog: mod.upsertAnalysisLog,
          appendUserAction: mod.appendUserAction,
        };
        console.log('[SafeInbox] Logger module enabled');
      }
    } catch {
      state.logger = null;
      console.log('[SafeInbox] Logger module unavailable (optional)');
    }
  }

  async function logAnalysisSafe({ emailData, scoreDetails, decision, mode = 'auto' }) {
    if (!state.logger || !isContextAlive()) return;
    try {
      const entry = await state.logger.upsertAnalysisLog({
        gmailUrl: window.location.href,
        email: emailData,
        analysis: {
          engine: 'full_scan',
          riskScore: Number(scoreDetails?.score ?? 0),
          reasons: Array.isArray(scoreDetails?.reasons) ? scoreDetails.reasons : [],
          threshold: state.threshold,
          mode,
        },
        decision,
      });
      state.currentViewId = entry?.viewId || state.currentViewId;
    } catch (err) {
      if (isContextInvalidatedError(err)) stopContext('logger invalidated');
      else console.warn('[SafeInbox] Optional analysis logging failed:', err);
    }
  }

  async function logActionSafe(type, details = {}) {
    if (!state.logger || !state.currentViewId || !isContextAlive()) return;
    try {
      await state.logger.appendUserAction(state.currentViewId, type, details);
    } catch (err) {
      if (isContextInvalidatedError(err)) stopContext('logger action invalidated');
      else console.warn('[SafeInbox] Optional action logging failed:', err);
    }
  }

  async function runFullAnalysis(emailData, { mode = 'auto' } = {}) {
    if (!isContextAlive()) return;
    if (typeof state.analyzeEmailFn !== 'function') {
      const mod = await import(chrome.runtime.getURL('utils/local_scanner.js'));
      state.analyzeEmailFn = mod?.analyzeEmail;
    }
    if (typeof state.analyzeEmailFn !== 'function') {
      throw new Error('analyzeEmail function unavailable');
    }

    const result = await state.analyzeEmailFn(emailData);
    if (!isContextAlive()) return;

    const score = Number(result?.score || 0);
    const reasons = Array.isArray(result?.reasons) ? result.reasons : [];
    const bannerShown = score >= state.threshold;
    
    if (bannerShown) postBannerData({ score, reasons }, emailData);
    else removeBanner();

    await logAnalysisSafe({
      emailData,
      scoreDetails: { score, reasons },
      decision: {
        bannerShown,
        trustedSender: false,
        ignoredSender: false,
        skipped: false,
        skipReason: null,
      },
      mode,
    });

    try {
          await chrome.storage.local.set({
            safeInboxReport: {
              score,
              reasons,
              email: emailData,
              timestamp: new Date().toISOString(),
            }
          });
        } catch (err) {
          console.warn('[SafeInbox] storage.session unavailable:', err);
        }
    return { score, reasons, bannerShown };
  }

  async function skipIgnoredSender(emailData) {
    removeBanner();
    clearHighlights();
    await logAnalysisSafe({
      emailData,
      scoreDetails: { score: 0, reasons: [] },
      decision: {
        bannerShown: false,
        trustedSender: false,
        ignoredSender: true,
        skipped: true,
        skipReason: 'ignored_sender',
      },
      mode: 'auto',
    });
  }

  async function waitForEmailReady(timeout = 4500) {
    const t0 = performance.now();
    while (performance.now() - t0 < timeout) {
      if (!isContextAlive()) return false;
      const subject = document.querySelector(SUBJECT_SELECTOR)?.innerText?.trim() || '';
      const body = document.querySelector(BODY_SELECTOR)?.innerText?.trim() || '';
      if (subject.length + body.length > 5) return true;
      await wait(100);
    }
    return false;
  }

  async function analyzeCurrentEmail({ force = false } = {}) {
    if (!isContextAlive()) return;
    if (state.analyzing) return;

    state.analyzing = true;
    try {
      if (!(await waitForEmailReady())) {
        removeBanner();
        clearHighlights();
        return;
      }
      if (!isContextAlive()) return;

      const emailData = extractEmailData();
      if (!emailData) {
        removeBanner();
        clearHighlights();
        return;
      }

      const hash = buildEmailHash(emailData);
      if (!force && hash === state.lastEmailHash) return;

      state.lastEmailHash = hash;
      state.lastEmailData = emailData;
      state.currentViewId = null;

      if (await isSenderIgnored(emailData.sender)) {
        await skipIgnoredSender(emailData);
        return;
      }

      const result = await runFullAnalysis(emailData, { mode: force ? 'forced' : 'auto' });
      if (!result) return;

      if (state.highlighted) applyHighlights(emailData);
    } catch (err) {
      if (isContextInvalidatedError(err)) {
        stopContext('analyze invalidated');
        return;
      }
      console.error('[SafeInbox] Analysis cycle failed:', err);
    } finally {
      state.analyzing = false;
    }
  }

  const debouncedAnalyze = debounce((opts) => {
    analyzeCurrentEmail(opts);
  }, 250);

  async function forceReanalysis(reason = 'manual') {
    if (!isContextAlive()) return;
    state.lastEmailHash = '';
    console.log(`[SafeInbox] Force re-analysis (${reason})`);
    debouncedAnalyze({ force: true });
  }

  function setupBannerMessageListener() {
    window.addEventListener('message', async (evt) => {
      if (!isContextAlive()) return;

      const banner = getBannerFrame();
      if (!banner || evt.source !== banner.contentWindow) return;

      const data = evt?.data;
      if (!data) return;

      try {
        if (typeof data === 'object' && data.type === 'apBannerResize') {
          const iframe = document.getElementById(BANNER_IFRAME_ID);
          if (iframe) {
            const h = Math.max(56, Math.min(520, Number(data.height || 56)));
            iframe.style.height = `${h}px`;
          }
          return;
        }

        if (data === 'manualAnalyze') {
          const fresh = extractEmailData();
          if (!fresh) return;
          if (await isSenderIgnored(fresh.sender)) {
            await skipIgnoredSender(fresh);
            return;
          }
          const res = await runFullAnalysis(fresh, { mode: 'manual' });
          await logActionSafe('manual_analysis', {
            score: Number(res?.score || 0),
            reasonCount: Array.isArray(res?.reasons) ? res.reasons.length : 0,
          });
          return;
        }

        if (data === 'dismissBanner') {
          removeBanner();
          await logActionSafe('dismiss_banner', { gmailUrl: window.location.href });
          return;
        }

        if (data === 'toggleHighlights') {
          toggleHighlights();
          await logActionSafe('toggle_highlights', { enabled: state.highlighted });
          return;
        }

        if (typeof data === 'object' && data.type === 'ignoreSender') {
          const senderToIgnore = (data.sender || state.lastEmailData?.sender || '').toLowerCase();
          if (senderToIgnore) {
            await addIgnoredSender(senderToIgnore);
            await logActionSafe('ignore_sender', { sender: senderToIgnore });
          }
          removeBanner();
          clearHighlights();
          await forceReanalysis('sender-ignored');
          return;
        }

        if (data === 'deepScanRequest') {
          console.log('[SafeInbox] Deep scan requested (placeholder)');
          await logActionSafe('deep_scan_requested', { gmailUrl: window.location.href });
        }
        if (data === 'openReport') {
          chrome.runtime.sendMessage({ 
            type: 'openReport',
            url: chrome.runtime.getURL('ui/report.html')  // ← chemin complet vers le fichier
          });
          return;
        }
      } catch (err) {
        if (isContextInvalidatedError(err)) {
          stopContext('message invalidated');
          return;
        }
        console.error('[SafeInbox] Banner message handling failed:', err);
      }
    });
  }

  function setupPopupMessageListener() {
    chrome.runtime.onMessage.addListener((msg) => {
      if (!isContextAlive() || !msg) return;

      if (msg.type === 'thresholdUpdated') {
        const next = Number(msg.newThreshold);
        if (Number.isFinite(next)) state.threshold = next;
        forceReanalysis('threshold-updated');
      }

      if (msg.type === 'ignoreListUpdated') {
        forceReanalysis('ignore-list-updated');
      }
    });
  }

  function setupDomObserver() {
    const target = document.querySelector(GMAIL_MAIN_SELECTOR);
    if (!target) {
      if (isContextAlive()) setTimeout(setupDomObserver, 300);
      return;
    }

    state.observer = new MutationObserver(() => debouncedAnalyze({ force: false }));
    state.observer.observe(target, { childList: true, subtree: true });

    window.addEventListener('hashchange', () => forceReanalysis('hashchange'));
    window.addEventListener('popstate', () => forceReanalysis('popstate'));

    console.log('[SafeInbox] Gmail observer initialized');
    setTimeout(() => debouncedAnalyze({ force: true }), 150);
  }

  try {
    window.addEventListener('beforeunload', () => stopContext('beforeunload'));
    window.addEventListener('pagehide', () => stopContext('pagehide'));

    const scannerModule = await import(chrome.runtime.getURL('utils/local_scanner.js'));
    await scannerModule.loadRules();
    state.analyzeEmailFn = scannerModule?.analyzeEmail || null;

    await maybeLoadLogger();
    await loadThreshold();

    setupBannerMessageListener();
    setupPopupMessageListener();
    setupDomObserver();
  } catch (err) {
    if (isContextInvalidatedError(err)) {
      stopContext('bootstrap invalidated');
      return;
    }
    console.error('[SafeInbox] Bootstrap failed:', err);
  }
})();
