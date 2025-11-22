(() => {
  const root    = document.getElementById('root');
  const bar     = document.getElementById('bar');
  const close   = document.getElementById('close');
  const panel   = document.getElementById('panel');
  const chips   = document.getElementById('reasonsChips');

  const manualBtn  = document.getElementById('manualAnalyzeBtn');
  const deepBtn    = document.getElementById('deepScanBtn');
  const hiBtn      = document.getElementById('highlightBtn');
  const ignBtn     = document.getElementById('ignoreBtn');
  const detailsBtn = document.getElementById('toggleDetails');
  const closePanel = document.getElementById('closePanelBtn');

  const prog     = document.getElementById('prog');
  const scoreNum = document.getElementById('scoreNum');

  let panelOpen = false;

  // --- Resize de l'iframe parent à la hauteur du contenu ---
  function sendResize() {
    const h = Math.ceil(document.documentElement.scrollHeight);
    window.parent.postMessage({ type: 'apBannerResize', height: h }, '*');
  }

  // --- Ouverture/fermeture du panneau avec animation + resize ---
  function slidePanel(open) {
    panelOpen = open;
    const full = panel.scrollHeight;

    if (open) {
      root.classList.add('open');
      panel.style.maxHeight = full + 'px';
    } else {
      panel.style.maxHeight = panel.scrollHeight + 'px';
      void panel.offsetHeight;               // reflow
      panel.style.maxHeight = '0px';
      setTimeout(() => root.classList.remove('open'), 320);
    }
    bar.setAttribute('aria-expanded', String(open));
    setTimeout(sendResize, 10);               // ajuste l'iframe après transition
  }

  // --- Anneau de score ---
  const r = 18;
  const C = 2 * Math.PI * r;
  if (prog) {
    prog.setAttribute('stroke-dasharray', String(C));
    prog.setAttribute('stroke-dashoffset', String(C));
  }

  function setSeverity(score) {
    const c = root.classList;
    c.remove('sev-low','sev-med','sev-high');
    if (score >= 70) c.add('sev-high');
    else if (score >= 40) c.add('sev-med');
    else c.add('sev-low');
  }

  function setScore(score) {
    const s = Math.max(0, Math.min(100, Number(score) || 0));
    const offset = C * (1 - s / 100);
    if (prog)     prog.setAttribute('stroke-dashoffset', String(offset));
    if (scoreNum) scoreNum.textContent = String(s);
    setSeverity(s);
  }

  // --- Réception des données {score, reasons, sender} ---
  window.addEventListener('message', ({ data }) => {
    
    if (!data) return;
    if (typeof data.score === 'number') setScore(data.score);

    chips.innerHTML = '';
    const arr = Array.isArray(data.reasons) ? data.reasons : [];
    arr.slice(0, 10).forEach(r => {
      const span = document.createElement('span');
      span.className = 'chip';
      span.textContent = r;
      chips.appendChild(span);
    });
    if (arr.length > 10) {
      const more = document.createElement('span');
      more.className = 'chip';
      more.textContent = `+${arr.length - 10} autres`;
      chips.appendChild(more);
    }
    window.__antiPhishSender = data.sender || '';

    // Si le panneau est ouvert et que le contenu change → ajuste hauteur
    if (panelOpen) {
      requestAnimationFrame(() => {
        panel.style.maxHeight = panel.scrollHeight + 'px';
        sendResize();
      });
    } else {
      // même fermé, s'assurer que la hauteur affichée (entête) est correcte
      sendResize();
    }
  });

  // --- Interactions ---
  // Clic entête → ouvre/ferme le panneau
  bar.addEventListener('click', (e) => {
    if (e.target === close) return;
    slidePanel(!panelOpen);
  });

  // Accessibilité clavier (Enter/Espace)
  bar.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      slidePanel(!panelOpen);
    }
  });

  // Fermer la bannière (bouton ×)
  close.addEventListener('click', (e) => {
    e.preventDefault();
    window.parent.postMessage('dismissBanner', '*');
  });

  // Boutons d'action
  manualBtn?.addEventListener('click', () => window.parent.postMessage('manualAnalyze', '*'));
  deepBtn  ?.addEventListener('click', () => window.parent.postMessage('deepScanRequest', '*'));
  hiBtn    ?.addEventListener('click', () => window.parent.postMessage('toggleHighlights', '*'));
  ignBtn   ?.addEventListener('click', () => {
    window.parent.postMessage({ type: 'ignoreSender', sender: window.__antiPhishSender || '' }, '*');
  });

  // Voir/masquer détails (chips)
  let detailsShown = false;
  detailsBtn?.addEventListener('click', () => {
    detailsShown = !detailsShown;
    chips.classList.toggle('show', detailsShown);
    detailsBtn.textContent = detailsShown ? 'Masquer détails' : 'Voir détails';

    if (panelOpen) {
      requestAnimationFrame(() => {
        panel.style.maxHeight = panel.scrollHeight + 'px';
        sendResize();
      });
    }
  });

  // Fermer le panneau (si bouton présent)
  closePanel?.addEventListener('click', () => slidePanel(false));

  // Ajustements sur resize de la fenêtre
  window.addEventListener('resize', () => {
    if (panelOpen) panel.style.maxHeight = panel.scrollHeight + 'px';
    sendResize();
  });

  // Première mesure à l'ouverture
  window.addEventListener('load', sendResize);
})();