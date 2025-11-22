// =============================================================
// 🛡️ SafeInbox - Popup principal
// Gère : seuil d’analyse + expéditeurs ignorés + synchro Gmail
// =============================================================

document.addEventListener("DOMContentLoaded", async () => {
    const thresholdInput = document.getElementById("threshold-input");
    const saveBtn = document.getElementById("save-btn");
    const saveStatus = document.getElementById("save-status");
    const toggleIgnoredBtn = document.getElementById("toggle-ignored");
    const ignoredContainer = document.getElementById("ignored-container");
    const arrow = document.getElementById("arrow");
    const ignoredList = document.getElementById("ignored-list");
    const clearBtn = document.getElementById("clear-list");
  
    // === Import du module utils/trusted.js ===
    const { removeIgnoredSender } = await import(
      chrome.runtime.getURL("utils/trusted.js")
    );
  
    /* ======================================================
       ⚙️ 1. Gestion du seuil d'analyse
       ====================================================== */
    const loadThreshold = async () => {
      const { threshold } = await chrome.storage.sync.get({ threshold: 40 });
      thresholdInput.value = threshold;
    };
  
    const saveThreshold = () => {
      const t = parseInt(thresholdInput.value, 10);
      if (isNaN(t) || t < 0 || t > 100) {
        alert("Seuil invalide (0-100)");
        return;
      }
  
      chrome.storage.sync.set({ threshold: t }, () => {
        saveStatus.textContent = `Seuil enregistré (${t}) ✅`;
        saveStatus.style.color = "#4CAF50";
        console.log("[SafeInbox] Seuil enregistré :", t);
        setTimeout(() => (saveStatus.textContent = ""), 2000);
      });
    };
  
    /* ======================================================
       📧 2. Affichage et gestion des expéditeurs ignorés
       ====================================================== */
    const renderIgnored = async () => {
      const { ignoredSenders = [] } = await chrome.storage.sync.get({
        ignoredSenders: [],
      });
  
      ignoredList.innerHTML = "";
  
      if (!ignoredSenders.length) {
        ignoredList.innerHTML = "<li><i>Aucun expéditeur ignoré</i></li>";
        return;
      }
  
      ignoredSenders.forEach((email) => {
        const li = document.createElement("li");
        li.innerHTML = `
          <span class="email">${email}</span>
          <span class="remove" title="Supprimer">×</span>
        `;
        li.querySelector(".remove").addEventListener("click", async () => {
          await removeIgnoredSender(email);
          await renderIgnored();
        });
        ignoredList.appendChild(li);
      });
    };
  
    const clearIgnored = async () => {
      if (confirm("Vider toute la liste des expéditeurs ignorés ?")) {
        await chrome.storage.sync.set({ ignoredSenders: [] });
        await renderIgnored();
      }
    };
  
    /* ======================================================
       📁 3. Gestion du repli / dépli
       ====================================================== */
    toggleIgnoredBtn.addEventListener("click", () => {
      const isCollapsed = ignoredContainer.classList.toggle("collapsed");
      arrow.textContent = isCollapsed ? "►" : "▼";
    });
  
    /* ======================================================
       🚀 4. Initialisation de l'interface
       ====================================================== */
    await loadThreshold();
    await renderIgnored();
  
    saveBtn.addEventListener("click", saveThreshold);
    clearBtn.addEventListener("click", clearIgnored);
  });
  
  /* ======================================================
     🔁 5. COMMUNICATION AVEC LE CONTENT SCRIPT (GMAIL)
     ====================================================== */
  
  // Lorsqu'on modifie le seuil d'analyse
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "sync" && changes.threshold) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: "thresholdUpdated",
            newThreshold: changes.threshold.newValue,
          });
          console.log(
            `[SafeInbox][Popup] Seuil mis à jour → ${changes.threshold.newValue}`
          );
        }
      });
    }
  });
  
  // Lorsqu'on modifie la liste des expéditeurs ignorés
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "sync" && changes.ignoredSenders) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          chrome.tabs.sendMessage(tabs[0].id, { type: "ignoreListUpdated" });
          console.log(
            "[SafeInbox][Popup] Liste ignorée mise à jour → notification envoyée"
          );
        }
      });
    }
  });