# Cyber Threat Intelligence Dashboard

Bienvenue sur mon tableau de bord de renseignement sur les cybermenaces.

L'objectif de ce projet est de consolider ma veille technologique en cybersécurité et de documenter mon portfolio. Ce dépôt est mis à jour quotidiennement et de façon 100% automatisée (grâce aux GitHub Actions) en agrégeant les flux RSS (tels que TheHackerNews, BleepingComputer) ainsi que les récentes vulnérabilités de l'API NVD du NIST.

## Suivi des Alertes

<!-- STATS_START -->
**Dernière mise à jour :** 04/04/2026 à 07:03  
**Total d'alertes collectées :** 15  
**Alertes Critiques/Hautes :** 0  
<!-- STATS_END -->

## ⚙️ Architecture & Stack Technologique

*   **Backend** : Python 3.10+ (`requests`, `feedparser`, `yaml`) fonctionnant via une approche Orientée Objet dynamique.
*   **Contrôle & Automation** : GitHub Actions (Cron Task) vérifiant la pertinence des changements pour maintenir un historique Git propre, sans commiter pour rien. 
*   **Web Frontend** : Hébergement via GitHub Pages. HTML5 Sémantique, CSS Vanilla (Design Premium et Dark Mode) et requêtes asynchrones en JS via Fetch.

Rejoignez le Dashboard interactif : [https://marco1t.github.io/Cyber-Threat-Intelligence-Dashboard/](https://marco1t.github.io/Cyber-Threat-Intelligence-Dashboard/)
