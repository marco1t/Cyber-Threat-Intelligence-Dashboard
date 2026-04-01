import os
import json
import yaml
import feedparser
import requests
from datetime import datetime
import logging

# Configuration de mes logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ThreatIntelFetcher:
    def __init__(self, config_path="config.yaml", data_path="data/data.json", readme_path="README.md"):
        self.config_path = config_path
        self.data_path = data_path
        self.readme_path = readme_path
        self.config = self._load_config()
        self.current_data = self._load_current_data()
        self.new_data = {"last_updated": datetime.now().isoformat(), "alerts": []}

    def _load_config(self):
        # Je charge ma configuration YAML
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Je n'ai pas pu charger ma configuration : {e}")
            return {}

    def _load_current_data(self):
        # Je lis mes données locales existantes pour pouvoir comparer ensuite
        if os.path.exists(self.data_path):
            try:
                with open(self.data_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Erreur lors de la lecture de mon fichier de données local : {e}")
        return {"alerts": []}

    def _check_keywords(self, text):
        # Je vérifie si mes mots-clés configurés sont présents dans le texte
        keywords = self.config.get("keywords", [])
        text_lower = text.lower()
        for kw in keywords:
            if kw.lower() in text_lower:
                return True
        return False

    def fetch_rss(self):
        # Je parcours mes flux RSS configurés
        rss_sources = self.config.get("sources", {}).get("rss", [])
        for source in rss_sources:
            logging.info(f"Je récupère le flux RSS de : {source['name']}")
            feed = feedparser.parse(source['url'])
            # Je prends seulement les 5 derniers articles pour ne pas surcharger
            for entry in feed.entries[:5]:
                title = entry.title
                summary = entry.get('summary', '')
                link = entry.link
                is_match = self._check_keywords(title + " " + summary)
                
                alert = {
                    "id": link,
                    "title": title,
                    "source": source['name'],
                    "type": "Article RSS",
                    "severity": "Info", 
                    "link": link,
                    "match": is_match,
                    "date": entry.get('published', datetime.now().isoformat())
                }
                self.new_data["alerts"].append(alert)

    def fetch_nist_cve(self):
        # Je récupère les vulnérabilités récentes depuis l'API NIST NVD
        logging.info("Je récupère les données de l'API NVD du NIST...")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # Je limite à 5 résultats pour faire simple et éviter le rate-limiting agressif
        params = {"resultsPerPage": 5}
        headers = {}
        
        # Je récupère ma clé d'API si elle est définie dans l'environnement
        nvd_api_key = os.environ.get("NVD_API_KEY")
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key
            logging.info("J'utilise ma clé d'API NVD pour contourner le rate-limit.")

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "Inconnu")
                    descriptions = cve.get("descriptions", [])
                    desc_text = descriptions[0].get("value", "") if descriptions else ""
                    
                    # Je cherche la sévérité (V3.1 ou V3.0)
                    metrics = cve.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                    severity = "Inconnu"
                    if cvss_data:
                        severity = cvss_data[0].get("cvssData", {}).get("baseSeverity", "Inconnu")

                    is_match = self._check_keywords(desc_text)
                    
                    alert = {
                        "id": cve_id,
                        "title": f"Vulnérabilité {cve_id}",
                        "source": "NIST NVD",
                        "type": "CVE",
                        "severity": severity,
                        "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "match": is_match,
                        "date": cve.get("published", datetime.now().isoformat())
                    }
                    self.new_data["alerts"].append(alert)
            else:
                logging.warning(f"L'API NIST a répondu avec le statut : {response.status_code}")
        except Exception as e:
            logging.error(f"Erreur lors de la requête vers le NIST : {e}")

    def has_new_data(self):
        # Je compare mes nouveaux IDs avec les anciens pour voir s'il y a du neuf
        old_ids = {alert["id"] for alert in self.current_data.get("alerts", [])}
        new_ids = {alert["id"] for alert in self.new_data["alerts"]}
        # Si au moins un nouvel ID n'est pas dans les anciens, je considère qu'il y a de nouvelles données
        return not new_ids.issubset(old_ids)

    def save_data(self):
        # J'enregistre mes données au format JSON
        try:
            with open(self.data_path, 'w', encoding='utf-8') as f:
                json.dump(self.new_data, f, ensure_ascii=False, indent=4)
            logging.info("J'ai sauvegardé mes nouvelles données JSON avec succès.")
        except Exception as e:
            logging.error(f"Je n'ai pas pu sauvegarder mon JSON : {e}")

    def update_readme(self):
        # Je mets à jour dynamiquement mon README contenant les statistiques
        try:
            critical_alerts = sum(1 for a in self.new_data["alerts"] if a.get("severity", "").upper() in ["CRITICAL", "HIGH"])
            total_alerts = len(self.new_data["alerts"])
            date_str = datetime.now().strftime("%d/%m/%Y à %H:%M")

            stats_block = (
                "<!-- STATS_START -->\n"
                f"**Dernière mise à jour :** {date_str}  \n"
                f"**Total d'alertes collectées :** {total_alerts}  \n"
                f"**Alertes Critiques/Hautes :** {critical_alerts}  \n"
                "<!-- STATS_END -->"
            )

            if os.path.exists(self.readme_path):
                with open(self.readme_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # J'utilise une simple substitution basée sur mes balises
                import re
                if "<!-- STATS_START -->" in content:
                    new_content = re.sub(
                        r"<!-- STATS_START -->.*<!-- STATS_END -->", 
                        stats_block, 
                        content, 
                        flags=re.DOTALL
                    )
                else:
                    new_content = content + "\n\n" + stats_block

                with open(self.readme_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                logging.info("J'ai mis à jour mon README.md avec mes nouvelles statistiques.")
            else:
                logging.warning("Le fichier README.md n'existe pas, je le crée.")
                with open(self.readme_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Cyber Threat Intelligence Dashboard\n\n{stats_block}\n")
        except Exception as e:
            logging.error(f"Erreur lors de la mise à jour de mon README : {e}")

    def run(self):
        # C'est la fonction principale de mon script
        logging.info("Je lance mon processus de récupération Threat Intel...")
        self.fetch_rss()
        self.fetch_nist_cve()
        
        if self.has_new_data():
            logging.info("J'ai trouvé de nouvelles données. Je procède à la sauvegarde.")
            self.save_data()
            self.update_readme()
        else:
            logging.info("Rien de nouveau sous le soleil. Je m'arrête ici pour ne pas polluer l'historique Git.")


if __name__ == "__main__":
    fetcher = ThreatIntelFetcher()
    fetcher.run()
