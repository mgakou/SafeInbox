# Communication entre `content.js`, `local_scanner.js`, `warning_banner.js` et `warning_banner.html`

Ce document explique, de façon concise et pragmatique, **qui fait quoi** et **comment** les fichiers de l’extension s’échangent les données. Pas de diagramme — juste du texte clair pour la doc ou README.

---

## Contexte rapide
Ton extension anti-phishing fonctionne en trois couches principales :
1. **Intégration / orchestration** — `content.js` (injecté dans la page Gmail).  
2. **Moteur d’analyse local** — `utils/local_scanner.js` (module JS importé).  
3. **Interface utilisateur** — `ui/warning_banner.html` + `ui/warning_banner.js` (chargés dans une `<iframe>` isolée).

Les communications utilisent deux mécanismes :
- **`import()` ES module** (synchronisation directe) entre `content.js` et `local_scanner.js`.  
- **`postMessage`** (window ↔ iframe) entre `content.js` et `warning_banner.js` (UI).

---

# 1. Rôles des fichiers

## `content.js`
- Injecté dans la page Gmail (content script).
- Observe le DOM (MutationObserver / hooks SPA) pour détecter quand un mail est affiché.
- Extrait `emailData` (subject, sender, senderName, body, links, attachments, anchors).
- Importe et appelle le moteur d’analyse (`local_scanner.js`).
- Injecte l’iframe de la bannière UI (`warning_banner.html`) et lui envoie les résultats via `iframe.contentWindow.postMessage(...)`.
- Reçoit les actions de l’UI via `window.addEventListener('message', ...)` et exécute : relancer l’analyse, surligner, ignorer expéditeur, déclencher deep scan (passer au background), fermer la bannière, ajuster la taille de l’iframe.

## `utils/local_scanner.js`
- Module JS exportant au minimum :
  - `loadRules()` — charge `rules.json` (dictionnaires) si nécessaire.
  - `analyzeEmail(emailData)` — calcule `{ score, reasons }`.
- Ne touche pas au DOM. Doit rester pur/portable pour réutilisation (Outlook/backend).
- Renvoie un objet simple utilisé ensuite par l’UI.

**Entrée** (exemple) :
```js
{
  subject: "Votre compte est bloqué",
  sender: "no-reply@bank-phish.tk",
  senderName: "Banque X Support",
  body: "Veuillez cliquer ici pour vérifier votre compte ...",
  links: ["http://phish.tk/login"],
  attachments: ["facture.zip"],
  anchors: [{ href, text }, ...]
}
```
**Sortie** (exemple) :
```js
{ score: 78, reasons: ["Mot clé 'bloqué'", "Lien vers IP directe", ...] }
```

## `ui/warning_banner.html` + `ui/warning_banner.js`
- `warning_banner.html` : structure HTML + styles (glass card, anneau de score, boutons).
- `warning_banner.js` :
  - Écoute `window.addEventListener('message', ...)` pour recevoir `{ score, reasons, sender }`.
  - Met à jour l’UI : anneau, texte, chips, sévérité (low/med/high).
  - Envoie des actions au parent (`window.parent.postMessage(...)`) : `manualAnalyze`, `deepScanRequest`, `toggleHighlights`, `dismissBanner`, `{ type:'ignoreSender', sender }` et `{ type:'apBannerResize', height }` pour redimensionner l’iframe.
  - Gère interactions (clics, clavier, accessibilité).

---

# 2. Formats et messages échangés

## 2.1 `content.js` → `local_scanner.js`
Appel direct via import et fonction :
```js
await loadRules();
const result = await analyzeEmail(emailData); // { score, reasons }
```

## 2.2 `content.js` → `warning_banner` (iframe)
Après analyse, envoi du résultat :
```js
iframe.contentWindow.postMessage({ score: 78, reasons: [...], sender: "no-reply@..." }, "*");
```
- cible : `warning_banner.js` côté iframe.
- le champ `reasons` est un tableau de chaînes descriptives.

## 2.3 `warning_banner` → `content.js`
UI envoie des messages user-driven vers le parent :
- Strings simples :
  - `"manualAnalyze"` — demande de relancer l’analyse locale immédiatement.
  - `"deepScanRequest"` — demande de déclencher l’analyse approfondie (backend).
  - `"toggleHighlights"` — demande de surligner/retirer surlignage dans le corps du mail.
  - `"dismissBanner"` — fermer la bannière.
- Objet :
  - `{ type: "ignoreSender", sender: "spam@domain" }` — ajouter à la whitelist/ignore locale.
  - `{ type: "apBannerResize", height: 230 }` — demander au parent d’ajuster la hauteur de l’iframe.

`content.js` doit vérifier `evt.data` avant d’agir (sanitiser).

---

# 3. Séquence typique (texte, sans diagramme)

1. `content.js` observe l’ouverture d’un mail, appelle `extractEmailData()` → obtient `emailData`.
2. `content.js` appelle `analyzeEmail(emailData)` (module `local_scanner.js` importé).
3. `local_scanner.js` renvoie `{ score, reasons }`.
4. Si score ≥ seuil, `content.js` injecte (ou met à jour) l’iframe `warning_banner.html`.
5. `content.js` envoie les données : `iframe.contentWindow.postMessage({ score, reasons, sender }, "*")`.
6. `warning_banner.js` affiche le score, les raisons et active les boutons.
7. L’utilisateur clique (par ex. “Surligner”). `warning_banner.js` envoie `window.parent.postMessage("toggleHighlights", "*")`.
8. `content.js` intercepte le message et exécute la fonction `highlightRisks(lastEmailData)` pour modifier le DOM du mail.
9. Si l’utilisateur demande “Analyse approfondie”, `content.js` relayera au `background.js` (ou envoie `chrome.runtime.sendMessage`) pour appeler le backend, puis récupère le résultat et met à jour la bannière.

---

# 4. Bonnes pratiques / sécurité liées à ces communications

- **Isolation de l’UI dans une iframe** : important pour éviter d’injecter du HTML directement dans Gmail (sécurité & compatibilité).
- **Origin checks** : aujourd’hui `postMessage(..., "*")` est utilisé pour simplicité — en prod, restreindre l’origine si possible, vérifier la forme du message (type / fields) avant d’agir.
- **Sanitiser les données** : ne jamais évaluer ou appliquer directement du HTML reçu ; les `reasons` restent du texte.
- **Permissions manifest** : déclarer `ui/*` dans `web_accessible_resources` pour que l’iframe soit chargée proprement.
- **Minimum permissions** dans `manifest.json` (éviter `<all_urls>` si pas nécessaire).
- **Ne pas divulguer de PII** : si tu envoies des données au backend, avertir l’utilisateur et proposer opt-in.

---

# 5. Conseils de debug (pratiques)

- **Console parent & iframe** : ouvrir la console Chrome pour la page Gmail (content script logs) et la console de l’iframe (sélectionner l’iframe dans Elements puis console ciblée).
- **Tracer les messages `postMessage`** :
  - `console.log("sending to banner", payload)` dans `content.js`.
  - `window.addEventListener('message', e => console.log("banner got", e.data))` dans `warning_banner.js`.
- **Vérifier les erreurs CORS / web_accessible_resources** si l’iframe ne charge pas.
- **Tester les actions utilisateur** : simuler `window.parent.postMessage('manualAnalyze', '*')` depuis la console de l’iframe et observer la réaction côté `content.js`.
- **Utiliser `chrome.storage`** pour vérifier saved states (ignored senders, threshold).

---

# 6. Points d’extension futurs (rapides)

- **Standardiser le format JSON d’échange** (`emailData` et `scoreDetails`) pour réutiliser le moteur sur Outlook ou backend.  
- **Ajouter un canal `chrome.runtime.sendMessage`** pour déléguer au `background.js` les appels réseau (deep scan) et renvoyer les résultats dans `content.js`.  
- **Mettre le moteur dans un Web Worker** si l’analyse locale devient lourde (performance).  
- **Versionning des règles (`rules.json`)** : `rulesVersion` envoyé avec `loadRules()` ; `content.js` peut demander mise à jour depuis le backend.

---

# 7. Exemples de messages (pour référence rapide)

- `content.js` → iframe :
```js
{ score: 85, reasons: ["Mot clé: urgent", "Raccourcisseur: bit.ly"], sender: "phish@domain.tk" }
```

- iframe → `content.js` :
```js
"manualAnalyze"
{ type: "ignoreSender", sender: "trusted@domain.com" }
{ type: "apBannerResize", height: 240 }
```

---

## Conclusion
- `content.js` orchestre : extraction, appel du moteur local, injection et communication avec l’UI.  
- `local_scanner.js` calcule le score et renvoie `{ score, reasons }`.  
- `warning_banner.html` + `warning_banner.js` affichent l’UI isolée, émettent les actions utilisateur par `postMessage`.  
- `postMessage` et `import()` sont les canaux ; respecter formats simples, validation, et sécurité améliore la robustesse.
