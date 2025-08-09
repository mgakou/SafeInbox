// popup.js
// Gère l'interface et les paramètres de l'extension

document.addEventListener('DOMContentLoaded', async () => {
    const thresholdInput = document.getElementById('threshold-input');
    const saveBtn = document.getElementById('save-btn');
    const lastScanBtn = document.getElementById('last-scan-btn');
    const scanResultDiv = document.getElementById('scan-result');

    // Charger le seuil enregistré (par défaut 40)
    const loadThreshold = async () => {
        const { threshold } = await chrome.storage.sync.get({ threshold: 10 });
        thresholdInput.value = threshold;
    };

    // Enregistrer le seuil lors du clic
    const saveThreshold = () => {
        const t = parseInt(thresholdInput.value, 10);
        if (isNaN(t) || t < 0 || t > 100) {
            alert('Seuil invalide (0-100)');
            return;
        }
        chrome.storage.sync.set({ threshold: t }, () => alert('Paramètres enregistrés'));
    };

    // Afficher le dernier rapport de scan approfondi
    const displayLastScanReport = () => {
        chrome.runtime.sendMessage({ action: 'getLastDeepScan' }, (response) => {
            if (response?.report) {
                const { score, summary, timestamp } = response.report;
                scanResultDiv.innerHTML = `
                    <p><strong>Score :</strong> ${score}/100</p>
                    <p><strong>Date :</strong> ${new Date(timestamp).toLocaleString()}</p>
                    <p><strong>Rapport :</strong> ${summary}</p>
                `;
            } else {
                scanResultDiv.textContent = 'Aucun scan disponible.';
            }
        });
    };

    // Ouvrir la politique de confidentialité dans un nouvel onglet
    const openPrivacyPolicy = (e) => {
        e.preventDefault();
        chrome.tabs.create({ url: chrome.runtime.getURL('privacy.html') });
    };

    await loadThreshold();
    saveBtn.addEventListener('click', saveThreshold);
    lastScanBtn.addEventListener('click', displayLastScanReport);
    document.getElementById('privacy-link').addEventListener('click', openPrivacyPolicy);
});
