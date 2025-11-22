**SafeInbox — Extension Chrome Anti-Phishing (Heuristique + Trusted Senders)**  
  
SafeInbox est une extension Chrome pour Gmail qui analyse automatiquement les emails afin d’identifier les tentatives de phishing grâce à un moteur heuristique avancé, une gestion dynamique des expéditeurs de confiance, et une interface utilisateur simple et efficace.  
  
L’extension est conçue pour être **rapide, locale, privée**, et prête à intégrer un **backend IA** pour l’analyse avancée.  
  
⸻  
  
**🚀 Fonctionnalités principales**  
  
**🔍 Analyse locale intelligent**  
  
Basée sur un moteur heuristique (local_scanner.js) :  
	•	Détection de mots clés suspects  
	•	Analyse du domaine, TLD, sous-domaines, liens raccourcis  
	•	Vérification des chemins suspects (/login, /verify, etc.)  
	•	Analyse des pièces jointes  
	•	Distance Levenshtein marque ↔ domaine (anti-spoofing)  
	•	Détection majuscules, ton alarmiste, points d’exclamation  
	•	Score global sur 100  
  
**Trusted Senders**  
  
3 niveaux de confiance :  
	•	email exact (ex : noreply@google.com)  
	•	domaine (doctolib.fr)  
	•	expéditeur ajouté manuellement via “Ignorer”  
  
**Bannière d’alerte Gmail**  
  
Interface flottante avec :  
	•	Score /100  
	•	Liste des risques détectés  
	•	Boutons :  
	•	Ignorer l’expéditeur  
	•	Surligner les risques  
	•	Analyse manuelle  
	•	Deep Scan (future feature)  
  
**Popup utilisateur**  
	•	Modifier le seuil d’analyse locale  
	•	Voir la liste des expéditeurs ignorés  
	•	Supprimer un expéditeur  
	•	Vider complètement la liste  
	•	Mise à jour dynamique sans recharger Gmail  
  
**Architecture du projet**  
  
**SafeInbox/**  
**├── manifest.json**  
**├── background/**  
**│   └── background.js**  
**├── content_scripts/**  
**│   └── content.js**  
**├── popup/**  
**│   ├── popup.html**  
**│   ├── popup.js**  
**│   └── style.css**  
**├── utils/**  
**│   ├── local_scanner.js**  
**│   ├── trusted.js**  
**│   ├── rules.json**  
**│   └── trusted_senders.json**  
**└── ui/**  
**    ├── warning_banner.html**  
**    ├── warning_banner.js**  
**    └── styles.css**  
  
  
##  Rôle détaillé de chaque fichier  
  
**manifest.json**  
  
Déclare l’extension Chrome :  
	•	Permissions  
	•	Scripts chargés (content, background, popup)  
	•	Accès à Gmail  
	•	Ressources accessibles  
	•	Options d’exécution  
  
C’est **le cœur de la configuration**.  
  
**content_scripts/content.js**  
  
Script injecté dans Gmail — **le centre nerveux de SafeInbox**.  
  
**Gère :**  
	•	Détection des emails via MutationObserver  
	•	Extraction des données (subject, sender, body, links…)  
	•	Analyse locale (analyzeEmail() ou lightCheckEmail())  
	•	Gestion bannière (injection / mise à jour / suppression)  
	•	Interaction Gmail SPA (pushState, replaceState, popstate)  
	•	Messages provenant du popup :  
	•	thresholdUpdated  
	•	ignoreListUpdated  
  
**utils/local_scanner.js**  
  
Moteur d’analyse locale (heuristique).  
  
Fonctions clés :  
	•	loadRules() → charge rules.json  
	•	analyzeEmail() → analyse complète  
	•	lightCheckEmail() → analyse légère (trusted sender)  
	•	Helpers :  
	•	baseDomain  
	•	distance Levenshtein  
	•	TLD risqués  
	•	chemins suspects  
	•	double extension  
	•	majuscules / ponctuation excessive  
  
C’est **le moteur anti-phishing local**.  
  
⸻  
  
**utils/trusted.js**  
  
Gestion de la **base de confiance**.  
  
Fusionne :  
	•	trusted_senders.json (base globale)  
	•	whitelistEmails (user)  
	•	whitelistDomains (user)  
	•	ignoredSenders (user)  
  
Fonctions :  
	•	getTrustedBase()  
	•	checkSenderTrusted()  
	•	addIgnoredSender()  
	•	removeIgnoredSender()  
	•	getUserWhitelist()  
  
C’est **la base dynamique des expéditeurs fiables**.  
  
⸻  
  
**utils/rules.json**  
  
Règles heuristiques :  
	•	mots clés  
	•	domaines à risque  
	•	TLD dangereux  
	•	raccourcisseurs d’URL  
	•	extensions à risque  
	•	domaines officiels par marque  
  
⸻  
  
**utils/trusted_senders.json**  
  
Base des expéditeurs légitimes connus :  
	•	emails officiels (ex : Google, Apple…)  
	•	domaines officiels  
	•	banques, SaaS, postes, plateformes gouvernementales  
**popup/popup.html — popup.js — style.css**  
  
Interface utilisateur pour configurer l’extension.  
  
**Contient :**  
	•	Seuil d’analyse (enregistré dynamiquement)  
	•	Liste des expéditeurs ignorés  
	•	Bouton de suppression  
	•	Bouton “Vider la liste”  
	•	Dépliables / repliables  
	•	Envoi de notifications → content_script  
	•	re-analyse instantanée dans Gmail  **ui/warning_banner.html — warning_banner.js**  
  
Bannière d’alerte avec :  
	•	Score  
	•	Expéditeur  
	•	Raison  
	•	Boutons d’action  
  
Injectée dans Gmail via un iframe.  
  
**background/background.js**  
  
Service worker.  
  
**Gère :**  
**Gère :**  
	•	future API backend (Deep Scan IA)  
	•	stockage du dernier scan (si activé)  
	•	notifications système  
