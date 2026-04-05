# 🛡️ SafeInbox

**Extension Chrome/Brave de détection de phishing pour Gmail — analyse 100% locale, zéro donnée envoyée à l'extérieur.**

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Chrome%20%7C%20Brave-orange)

---

## Présentation

SafeInbox analyse automatiquement chaque email ouvert dans Gmail et calcule un score de risque basé sur des règles locales. Si le score dépasse le seuil configuré (40 par défaut), une bannière d'alerte apparaît en bas à droite de la page avec les actions disponibles.

Tout se passe dans le navigateur. Aucun email, aucune URL, aucune donnée personnelle n'est transmise à un serveur externe.

---

## Fonctionnalités

### Détection locale
- Analyse des mots-clés suspects (urgence, mot de passe, compte bloqué…)
- Détection des liens non sécurisés (HTTP, IP directe, liens `data:`)
- Détection des raccourcisseurs d'URL (bit.ly, tinyurl, rb.gy…)
- Détection des TLD à risque (`.xyz`, `.tk`, `.top`, `.click`…)
- Détection des sous-domaines profonds
- Détection des chemins d'hameçonnage (`/login`, `/verify`, `/confirm`…)
- Vérification des pièces jointes dangereuses (`.exe`, `.js`, `.docm`…)
- Détection des doubles extensions (`.pdf.exe`, `.doc.js`…)
- Détection du spoofing de marques (PayPal, Google, Apple, banques françaises…)
- Détection des ancres trompeuses (texte ≠ URL réelle)
- Analyse de la ponctuation alarmiste et des majuscules excessives

### Interface
- **Bannière contextuelle** — apparaît sur Gmail, score visible, actions rapides
- **Page de rapport** — analyse complète avec signaux groupés par sévérité (Critique / Suspect / Attention)
- **Surlignage** — mise en évidence des liens et pièces jointes suspects directement dans l'email
- **Popup de configuration** — seuil d'alerte, expéditeurs ignorés, export JSON de l'historique

### Actions utilisateur
- Relancer l'analyse manuellement
- Surligner les éléments suspects dans l'email
- Ignorer un expéditeur (désactive l'analyse pour cet email exact)
- Voir le rapport complet dans un onglet dédié
- Analyse approfondie IA *(à venir)*

---

## Structure du projet

```
safeinbox/
├── background/
│   └── background.js          # Service worker — gestion des messages et deep scan
├── content_scripts/
│   └── content.js             # Script principal injecté dans Gmail
├── popup/
│   ├── popup.html             # Interface de configuration
│   ├── popup.js
│   └── style.css
├── ui/
│   ├── warning_banner.html    # Bannière d'alerte (iframe injectée dans Gmail)
│   ├── warning_banner.js
│   ├── styles.css
│   ├── report.html            # Page de rapport d'analyse
│   └── report.js
├── utils/
│   ├── local_scanner.js       # Moteur de scoring local
│   ├── rules.json             # Règles de détection (mots-clés, marques, TLD...)
│   ├── logger.js              # Journalisation locale (chrome.storage.local)
│   ├── trusted.js             # Gestion des expéditeurs de confiance
│   └── trusted_senders.json  # Liste de référence des emails légitimes connus
├── tests/                     # Outils de test (exclus du build de production)
│   ├── test_harness.html
│   ├── test_harness.js
│   └── test_samples.json
└── manifest.json
```

---

## Installation (mode développeur)

1. Clone le dépôt
```bash
git clone https://github.com/mgakou/safeinbox.git
```

2. Ouvre Chrome ou Brave et navigue vers `chrome://extensions` ou `brave://extensions`

3. Active le **Mode développeur** (toggle en haut à droite)

4. Clique sur **Charger l'extension non empaquetée** et sélectionne le dossier `safeinbox/`

5. Ouvre Gmail — l'extension est active immédiatement

---

## Tester le moteur de scoring

Un harness de test est disponible à la racine du projet. Pour l'utiliser :

1. Récupère l'ID de ton extension depuis `chrome://extensions`
2. Ouvre `chrome-extension://[TON_ID]/tests/test_harness.html`
3. Clique **Lancer tous les tests**

Le harness exécute 19 cas de test (phishing, emails légitimes, cas limites, faux positifs potentiels) et affiche les scores, raisons et verdicts pour chaque cas.

---

## Configuration

Via le popup de l'extension :

| Paramètre | Défaut | Description |
|---|---|---|
| Seuil d'alerte | 40 | Score minimum pour afficher la bannière |
| Expéditeurs ignorés | — | Liste des emails jamais analysés |

---

## Système de scoring

Le score final est compris entre 0 et 100. Chaque règle ajoute des points :

| Signal | Points |
|---|---|
| Mot-clé suspect | +5 |
| Ponctuation alarmiste | +4 |
| Raccourcisseur d'URL | +8 |
| Lien HTTP non sécurisé | +3 |
| Lien vers IP directe | +10 |
| TLD risqué | +6 |
| Chemin d'hameçonnage | +6 |
| Sous-domaine profond | +4 |
| Spoofing de marque (lien) | +10 |
| Spoofing de marque (expéditeur) | +10 |
| Ancre trompeuse | +15 |
| URL affichée ≠ URL réelle | +12 |
| Pièce jointe dangereuse | +12 |
| Double extension | +10 |
| Liens officiels uniquement (atténuation) | -8 |

---

## Rapport d'analyse

Accessible via le bouton **Voir rapport** dans la bannière, le rapport affiche :

- Score global avec jauge visuelle et niveau de sévérité
- Métadonnées de l'email (expéditeur, sujet, nombre de liens)
- Signaux détectés groupés par niveau : **Critique** / **Suspect** / **Attention**
- Liste de tous les liens avec leurs indicateurs de risque individuels
- Placeholder pour l'analyse IA à venir

---

## Roadmap

- [x] Moteur de scoring local basé sur règles JSON
- [x] Bannière contextuelle avec score et actions
- [x] Page de rapport d'analyse complète
- [x] Journalisation locale des analyses
- [x] Détection des ancres trompeuses
- [ ] Détection des homoglyphes (caractères cyrilliques/grecs)
- [ ] Analyse d'entropie des domaines (détection DGA)
- [ ] Résolution locale des raccourcisseurs d'URL
- [ ] Analyse approfondie via IA (opt-in, API externe)
- [ ] Support multilingue des règles de détection

---

## Vie privée

SafeInbox ne collecte, ne transmet et ne stocke aucune donnée en dehors de votre navigateur.

- L'analyse se fait entièrement en local
- L'historique des analyses est stocké dans `chrome.storage.local` (votre navigateur uniquement)
- Aucune télémétrie, aucun tracker, aucune publicité
- Le code source est entièrement lisible et auditable

---

## Contribuer

Les contributions sont les bienvenues. Pour proposer une amélioration des règles de détection, modifier `utils/rules.json` et tester via le harness avant de soumettre une PR.

---

## Licence

MIT — libre d'utilisation, de modification et de distribution.
