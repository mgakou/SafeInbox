document.addEventListener('DOMContentLoaded', () => {
    const menuBtn     = document.getElementById('menuBtn');      // ✅ correct ID
    const closeBtn    = document.getElementById('closeBtn');     // ✅ correct ID
    const popupMenu   = document.getElementById('popupMenu');    // ✅ correct ID
    const saveBtn     = document.getElementById('saveThresholdBtn'); // ✅
    const thresholdInput = document.getElementById('thresholdInput'); // ✅
    const scanBtn     = document.getElementById('scanBtn');      // nouveau bouton analyse locale
    const deepScanBtn = document.getElementById('deepScanBtn');  // nouveau bouton analyse backend

    // Fermer popup
    closeBtn.addEventListener('click', () => window.close());

    // Affichage menu
    menuBtn.addEventListener('click', (e) => {
      e.stopPropagation(); // Empêche la propagation pour l'écouteur global
      popupMenu.classList.toggle('hidden');
    });

    // UX bonus: Fermer le menu si on clique en dehors
    document.addEventListener('click', (e) => {
      if (!popupMenu.classList.contains('hidden')) {
        // Si le clic n'est ni sur le menu ni sur le bouton menu, on ferme
        if (!popupMenu.contains(e.target) && e.target !== menuBtn) {
          popupMenu.classList.add('hidden');
        }
      }
    });

    // Seuil
    chrome.storage.sync.get({ threshold: 40 }, ({ threshold }) => {
      thresholdInput.value = threshold;
    });

    saveBtn.addEventListener('click', () => {
      const val = parseInt(thresholdInput.value);
      if (!isNaN(val) && val >= 0 && val <= 100) {
        chrome.storage.sync.set({ threshold: val }, () => {
          alert('Seuil enregistré.');
          popupMenu.classList.add('hidden');
        });
      } else {
        alert("Veuillez entrer un nombre entre 0 et 100.");
      }
    });

    // Bouton analyse locale
    scanBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'scan' });
    });

    // Bouton analyse backend
    deepScanBtn.addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'deepScan' });
    });
  });