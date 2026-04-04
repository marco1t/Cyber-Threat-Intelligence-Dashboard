import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import feedparser
import requests
import yaml

# Configuration de mes logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ThreatIntelFetcher:
    def __init__(self, config_path="config.yaml", data_path="docs/data/data.json", readme_path="README.md"):
        self.config_path = config_path
        self.data_path = data_path
        self.readme_path = readme_path
        self.run_started_at = datetime.now(timezone.utc)
        self.config = self._load_config()
        self.settings = self.config.get("settings", {})
        self.current_data = self._load_current_data()
        self.force_daily_snapshot = bool(self.settings.get("force_daily_snapshot", False))
        self.cve_days_window = int(self.settings.get("cve_days_window", 7))
        self.max_entries_per_rss_source = int(self.settings.get("max_entries_per_rss_source", 5))
        self.max_nvd_results = int(self.settings.get("max_nvd_results", 10))
        self.request_timeout = int(self.settings.get("request_timeout", 15))
        self.source_attempts = 0
        self.successful_sources = []
        self.failed_sources = []
        self.new_data = {"last_updated": self._format_iso(self.run_started_at), "alerts": []}

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

    def _format_iso(self, dt):
        if dt is None:
            dt = self.run_started_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

    def _parse_datetime(self, value):
        if not value:
            return None

        if isinstance(value, datetime):
            dt = value
        else:
            text = str(value).strip()
            try:
                dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                try:
                    dt = parsedate_to_datetime(text)
                except (TypeError, ValueError):
                    return None

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    def _normalize_date(self, value):
        parsed = self._parse_datetime(value)
        if parsed is None:
            parsed = self.run_started_at
        return self._format_iso(parsed)

    def _register_source_result(self, source_name, success, reason=None):
        self.source_attempts += 1
        if success:
            self.successful_sources.append(source_name)
            return

        failure = {"source": source_name}
        if reason:
            failure["reason"] = reason
        self.failed_sources.append(failure)

    def _extract_severity(self, metrics):
        for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_entries = metrics.get(metric_key, [])
            if not metric_entries:
                continue

            metric = metric_entries[0]
            severity = metric.get("baseSeverity")
            if severity:
                return severity

            severity = metric.get("cvssData", {}).get("baseSeverity")
            if severity:
                return severity

        return "Inconnu"

    def _finalize_alerts(self):
        deduplicated_alerts = {}

        for alert in self.new_data["alerts"]:
            alert_id = alert.get("id")
            if not alert_id:
                continue

            normalized_alert = dict(alert)
            normalized_alert["date"] = self._normalize_date(normalized_alert.get("date"))
            current_entry = deduplicated_alerts.get(alert_id)

            if current_entry is None:
                deduplicated_alerts[alert_id] = normalized_alert
                continue

            current_date = self._parse_datetime(current_entry.get("date"))
            candidate_date = self._parse_datetime(normalized_alert.get("date"))
            if candidate_date and (current_date is None or candidate_date >= current_date):
                deduplicated_alerts[alert_id] = normalized_alert

        self.new_data["alerts"] = sorted(
            deduplicated_alerts.values(),
            key=lambda alert: self._parse_datetime(alert.get("date")) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

    def _check_keywords(self, text):
        # Je vérifie si mes mots-clés configurés sont présents dans le texte
        keywords = self.config.get("keywords", [])
        text_lower = (text or "").lower()
        for kw in keywords:
            if kw.lower() in text_lower:
                return True
        return False

    def fetch_rss(self):
        # Je parcours mes flux RSS configurés
        rss_sources = self.config.get("sources", {}).get("rss", [])
        for source in rss_sources:
            source_name = source.get("name", "Source RSS inconnue")
            source_url = source.get("url")
            logging.info(f"Je récupère le flux RSS de : {source_name}")

            try:
                feed = feedparser.parse(source_url)
                status_code = getattr(feed, "status", 200)
                entries = getattr(feed, "entries", [])

                if status_code >= 400:
                    raise ValueError(f"HTTP {status_code}")
                if getattr(feed, "bozo", 0) and not entries:
                    raise ValueError(str(getattr(feed, "bozo_exception", "Flux RSS invalide")))

                for index, entry in enumerate(entries[: self.max_entries_per_rss_source], start=1):
                    title = entry.get("title", "Article RSS")
                    summary = entry.get("summary", "") or entry.get("description", "")
                    link = entry.get("link") or f"{source_url}#entry-{index}"
                    is_match = self._check_keywords(f"{title} {summary}")

                    alert = {
                        "id": link,
                        "title": title,
                        "source": source_name,
                        "type": "Article RSS",
                        "severity": "Info",
                        "link": link,
                        "match": is_match,
                        "date": self._normalize_date(
                            entry.get("published") or entry.get("updated") or entry.get("created")
                        ),
                    }
                    self.new_data["alerts"].append(alert)

                self._register_source_result(source_name, True)
            except Exception as e:
                logging.warning(f"Le flux {source_name} a échoué : {e}")
                self._register_source_result(source_name, False, str(e))

    def fetch_nist_cve(self):
        # Je récupère les vulnérabilités récentes depuis l'API NIST NVD
        logging.info("Je récupère les données de l'API NVD du NIST...")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        end_date = self.run_started_at
        start_date = end_date - timedelta(days=self.cve_days_window)
        params = {
            "resultsPerPage": self.max_nvd_results,
            "pubStartDate": self._format_iso(start_date),
            "pubEndDate": self._format_iso(end_date),
        }
        headers = {}
        
        # Je récupère ma clé d'API si elle est définie dans l'environnement
        nvd_api_key = os.environ.get("NVD_API_KEY")
        if nvd_api_key:
            headers["apiKey"] = nvd_api_key
            logging.info("J'utilise ma clé d'API NVD pour contourner le rate-limit.")

        try:
            response = requests.get(url, headers=headers, params=params, timeout=self.request_timeout)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            fresh_alerts = []

            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "Inconnu")
                descriptions = cve.get("descriptions", [])
                desc_text = descriptions[0].get("value", "") if descriptions else ""
                published_at = self._parse_datetime(cve.get("published"))

                if published_at is None:
                    continue
                if published_at < start_date or published_at > end_date:
                    continue

                metrics = cve.get("metrics", {})
                severity = self._extract_severity(metrics)
                is_match = self._check_keywords(desc_text)

                fresh_alerts.append(
                    {
                        "id": cve_id,
                        "title": f"Vulnérabilité {cve_id}",
                        "source": "NIST NVD",
                        "type": "CVE",
                        "severity": severity,
                        "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "match": is_match,
                        "date": self._format_iso(published_at),
                    }
                )

            fresh_alerts.sort(key=lambda alert: self._parse_datetime(alert["date"]), reverse=True)
            self.new_data["alerts"].extend(fresh_alerts[: self.max_nvd_results])
            self._register_source_result("NIST NVD", True)
        except Exception as e:
            logging.error(f"Erreur lors de la requête vers le NIST : {e}")
            self._register_source_result("NIST NVD", False, str(e))

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
            
            # Je sauvegarde également une archive pour la date courante
            today_str = self.run_started_at.strftime("%Y-%m-%d")
            data_dir = os.path.dirname(self.data_path)
            daily_path = os.path.join(data_dir, f"{today_str}.json")
            with open(daily_path, 'w', encoding='utf-8') as f:
                json.dump(self.new_data, f, ensure_ascii=False, indent=4)
                
            # Je mets à jour mon index.json contenant l'historique
            index_path = os.path.join(data_dir, "index.json")
            index_data = []
            if os.path.exists(index_path):
                try:
                    with open(index_path, 'r', encoding='utf-8') as f:
                        index_data = json.load(f)
                except Exception:
                    pass
            
            # Je retire l'entrée du jour si elle existe déjà, pour la remplacer
            index_data = [item for item in index_data if item.get("date") != today_str]
            critical_alerts = sum(1 for a in self.new_data["alerts"] if a.get("severity", "").upper() in ["CRITICAL", "HIGH"])
            
            index_data.append({
                "date": today_str,
                "file": f"{today_str}.json",
                "total_cves": len(self.new_data["alerts"]),
                "critical_cves": critical_alerts
            })
            
            # Je trie par date croissante par sécurité
            index_data = sorted(index_data, key=lambda x: x["date"])
            
            with open(index_path, 'w', encoding='utf-8') as f:
                json.dump(index_data, f, ensure_ascii=False, indent=4)
            logging.info("J'ai mis à jour l'historique et index.json.")
        except Exception as e:
            logging.error(f"Je n'ai pas pu sauvegarder mon JSON : {e}")

    def update_readme(self):
        # Je mets à jour dynamiquement mon README contenant les statistiques
        try:
            critical_alerts = sum(1 for a in self.new_data["alerts"] if a.get("severity", "").upper() in ["CRITICAL", "HIGH"])
            total_alerts = len(self.new_data["alerts"])
            date_str = self.run_started_at.astimezone(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC")

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
        self._finalize_alerts()

        if self.source_attempts == 0:
            raise RuntimeError("Aucune source n'est configurée pour la collecte.")
        if not self.successful_sources:
            raise RuntimeError("Toutes les sources ont échoué. Snapshot annulé pour préserver les données existantes.")

        if self.failed_sources:
            logging.warning(f"Sources en échec pendant cette exécution : {self.failed_sources}")

        if not self.new_data["alerts"]:
            logging.warning("La collecte s'est terminée sans aucune alerte exploitable.")

        if self.force_daily_snapshot or self.has_new_data():
            logging.info("Je procède à la sauvegarde du snapshot quotidien.")
            self.save_data()
            self.update_readme()
        else:
            logging.info("Aucun changement détecté et snapshot quotidien désactivé. Je ne sauvegarde rien.")


if __name__ == "__main__":
    fetcher = ThreatIntelFetcher()
    fetcher.run()
