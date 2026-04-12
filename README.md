# Cyber Threat Intelligence Dashboard

Bienvenue sur mon tableau de bord de renseignement sur les cybermenaces.

L'objectif de ce projet est de consolider ma veille technologique en cybersécurité et de documenter mon portfolio. Ce dépôt est mis à jour quotidiennement et de façon 100% automatisée (grâce aux GitHub Actions) en agrégeant plusieurs flux RSS cyber ainsi que les vulnérabilités publiées récemment sur l'API NVD du NIST.

## Suivi des Alertes

<!-- STATS_START -->
**Dernière mise à jour :** 12/04/2026 à 07:17 UTC  
**Total d'alertes collectées :** 40  
**Alertes Critiques/Hautes :** 2  
<!-- STATS_END -->

## ⚙️ Architecture & Stack Technologique

*   **Backend** : Python 3.10+ (`requests`, `feedparser`, `yaml`) fonctionnant via une approche Orientée Objet dynamique.
*   **Contrôle & Automation** : GitHub Actions (Cron Task) générant un snapshot quotidien, mettant à jour le dashboard et empêchant l'écrasement des données si toutes les sources échouent.
*   **Web Frontend** : Hébergement via GitHub Pages. HTML5 Sémantique, CSS Vanilla (Design Premium et Dark Mode) et requêtes asynchrones en JS via Fetch.

Rejoignez le Dashboard interactif : [https://marco1t.github.io/Cyber-Threat-Intelligence-Dashboard/](https://marco1t.github.io/Cyber-Threat-Intelligence-Dashboard/)
