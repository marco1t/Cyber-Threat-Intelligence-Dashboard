import html
import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse

import feedparser
import requests
import yaml
from bs4 import BeautifulSoup


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class ThreatIntelFetcher:
    def __init__(self, config_path="config.yaml", data_path="docs/data/data.json", readme_path="README.md"):
        self.config_path = config_path
        self.data_path = data_path
        self.readme_path = readme_path
        self.run_started_at = datetime.now(timezone.utc)
        self.config = self._load_config()
        self.settings = self.config.get("settings", {})
        self.sources = self.config.get("sources", {})
        self.preferences = self.config.get("preferences", {})
        self.current_data = self._load_current_data()

        self.force_daily_snapshot = bool(self.settings.get("force_daily_snapshot", True))
        self.enable_nvd = bool(self.settings.get("enable_nvd", False))
        self.request_timeout = int(self.settings.get("request_timeout", 15))
        self.max_entries_per_source = int(self.settings.get("max_entries_per_source", 8))
        self.max_items_per_stream = int(self.settings.get("max_items_per_stream", 5))
        self.sitemap_days_window = int(self.settings.get("sitemap_days_window", 45))
        self.dedupe_similarity_threshold = float(self.settings.get("dedupe_similarity_threshold", 0.88))
        self.cyber_min_score = float(self.settings.get("cyber_min_score", 7.0))
        self.ai_min_score = float(self.settings.get("ai_min_score", 7.0))

        self.source_attempts = 0
        self.successful_sources = []
        self.failed_sources = []

        self.new_data = {
            "last_updated": self._format_iso(self.run_started_at),
            "alerts": [],
            "streams": {"cyber": [], "ai": []},
            "summary": {},
        }

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ThreatIntelDashboard/3.0"})

        self.ai_company_aliases = {
            "OpenAI": ["openai", "chatgpt", "codex", "gpt", "sora", "responses api", "operator"],
            "Anthropic": ["anthropic", "claude", "claude code", "opus", "sonnet", "haiku", "claude.ai"],
        }
        self.ai_focus_aliases = [
            "model",
            "models",
            "feature",
            "features",
            "release",
            "launch",
            "benchmark",
            "security",
            "incident",
            "outage",
            "reasoning",
            "memory",
            "agent",
            "api",
            "pricing",
            "update",
            "copilot",
        ]
        self.cyber_priority_aliases = [
            "incident",
            "breach",
            "campaign",
            "ransomware",
            "malware",
            "phishing",
            "supply chain",
            "threat actor",
            "apt",
            "exploit",
            "zero-day",
            "actively exploited",
            "compromise",
            "intrusion",
            "outage",
            "backdoor",
        ]

    def _load_config(self):
        try:
            with open(self.config_path, "r", encoding="utf-8") as file_obj:
                return yaml.safe_load(file_obj) or {}
        except Exception as exc:
            logging.error(f"Je n'ai pas pu charger la configuration : {exc}")
            return {}

    def _load_current_data(self):
        if os.path.exists(self.data_path):
            try:
                with open(self.data_path, "r", encoding="utf-8") as file_obj:
                    return json.load(file_obj)
            except Exception as exc:
                logging.error(f"Erreur pendant la lecture des données courantes : {exc}")
        return {"alerts": [], "streams": {"cyber": [], "ai": []}}

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

    def _clean_text(self, text):
        if not text:
            return ""
        cleaned = re.sub(r"<[^>]+>", " ", str(text))
        cleaned = html.unescape(cleaned)
        return re.sub(r"\s+", " ", cleaned).strip()

    def _shorten(self, text, limit=180):
        cleaned = self._clean_text(text)
        if len(cleaned) <= limit:
            return cleaned
        return cleaned[: limit - 1].rstrip() + "…"

    def _slug_to_title(self, slug):
        raw = slug.replace("-", " ").replace("_", " ").strip()
        title = re.sub(r"\s+", " ", raw).title()
        replacements = {
            "Gpt": "GPT",
            "Api": "API",
            "Ai": "AI",
            "Openai": "OpenAI",
            "Chatgpt": "ChatGPT",
            "Codex": "Codex",
            "Claude": "Claude",
            "Aws": "AWS",
        }
        for original, replacement in replacements.items():
            title = title.replace(original, replacement)
        return title

    def _normalize_title(self, text):
        lowered = self._clean_text(text).lower()
        lowered = re.sub(r"[^a-z0-9\s]", " ", lowered)
        lowered = re.sub(r"\s+", " ", lowered).strip()
        return lowered

    def _collect_matches(self, text, terms):
        matches = []
        haystack = text.lower()
        for term in terms:
            term_lower = term.lower()
            if term_lower in haystack:
                matches.append(term)
        return matches

    def _is_official_source(self, source_name):
        official_markers = (
            "openai",
            "anthropic",
            "claude",
            "github changelog",
            "cisa",
            "microsoft security blog",
            "aws security blog",
        )
        source_lower = source_name.lower()
        return any(marker in source_lower for marker in official_markers)

    def _compute_reason(self, official, company_hits, focus_hits, stack_hits, stream):
        parts = []
        if official:
            parts.append("source officielle")
        if company_hits:
            parts.append(", ".join(company_hits[:2]))
        if focus_hits:
            parts.append(", ".join(focus_hits[:2]))
        if stack_hits and stream == "cyber":
            parts.append(", ".join(stack_hits[:2]))
        return " | ".join(parts[:3])

    def _classify_alert(self, stream, source, title, summary):
        text = f"{title} {summary}".strip()
        source_name = source.get("name", "Source")
        source_weight = float(source.get("weight", 1.0))
        official = self._is_official_source(source_name)
        score = source_weight
        tags = []

        stack_terms = self.preferences.get("dev_stack_terms", [])
        stack_hits = self._collect_matches(text, stack_terms)
        score += len(stack_hits) * 1.2
        tags.extend(stack_hits[:3])

        if stream == "cyber":
            focus_hits = self._collect_matches(text, self.preferences.get("cyber_focus_terms", []))
            priority_hits = self._collect_matches(text, self.cyber_priority_aliases)
            score += len(focus_hits) * 2.0
            score += len(priority_hits) * 2.5
            if official:
                score += 1.5
            if "cve-" in text.lower():
                score -= 4.0
            tags.extend(focus_hits[:3])
            tags.extend(priority_hits[:3])
            match = score >= self.cyber_min_score or bool(stack_hits)
            reason = self._compute_reason(official, [], focus_hits or priority_hits, stack_hits, stream)
            return score, match, tags, reason

        company_hits = []
        for company in self.preferences.get("companies", []):
            aliases = self.ai_company_aliases.get(company, [company])
            if self._collect_matches(text, aliases):
                company_hits.append(company)

        focus_terms = list(self.preferences.get("ai_focus_terms", [])) + self.ai_focus_aliases
        focus_hits = self._collect_matches(text, focus_terms)

        score += len(company_hits) * 3.0
        score += len(focus_hits) * 1.8
        if official:
            score += 2.0

        if source_name in {"OpenAI Status", "Claude Status", "Claude Code Releases", "Anthropic News", "OpenAI Updates"}:
            score += 2.5

        tags.extend(company_hits[:2])
        tags.extend(focus_hits[:4])

        # The serious external media only matters if it mentions the target companies or products.
        if source_name in {"The Verge AI", "TechCrunch AI"} and not company_hits:
            score = 0.0

        match = score >= self.ai_min_score and (bool(company_hits) or official)
        reason = self._compute_reason(official, company_hits, focus_hits, [], stream)
        return score, match, tags, reason

    def _make_alert(self, stream, source, title, link, summary="", date=None, severity="Info", alert_type="Article"):
        clean_title = self._clean_text(title)
        clean_summary = self._shorten(summary)
        if not clean_title or not link:
            return None

        score, match, tags, reason = self._classify_alert(stream, source, clean_title, clean_summary)
        minimum_score = self.cyber_min_score if stream == "cyber" else self.ai_min_score
        if score < minimum_score and not match:
            return None

        return {
            "id": link,
            "title": clean_title,
            "summary": clean_summary,
            "source": source.get("name", "Source"),
            "type": alert_type,
            "severity": severity,
            "link": link,
            "match": match,
            "date": self._normalize_date(date),
            "stream": stream,
            "score": round(score, 1),
            "reason": reason,
            "tags": list(dict.fromkeys(tags))[:5],
        }

    def _register_source_result(self, source_name, success, reason=None):
        self.source_attempts += 1
        if success:
            self.successful_sources.append(source_name)
            return

        failure = {"source": source_name}
        if reason:
            failure["reason"] = reason
        self.failed_sources.append(failure)

    def _append_alert(self, alert):
        if alert:
            self.new_data["alerts"].append(alert)

    def fetch_rss_sources(self, sources, stream):
        for source in sources:
            source_name = source.get("name", "Source RSS inconnue")
            source_url = source.get("url")
            logging.info(f"Je récupère le flux RSS de : {source_name}")
            try:
                feed = feedparser.parse(source_url)
                status_code = getattr(feed, "status", 200)
                entries = getattr(feed, "entries", [])

                if status_code and status_code >= 400:
                    raise ValueError(f"HTTP {status_code}")
                if getattr(feed, "bozo", 0) and not entries:
                    raise ValueError(str(getattr(feed, "bozo_exception", "Flux RSS invalide")))

                for entry in entries[: self.max_entries_per_source]:
                    title = entry.get("title", "Entrée RSS")
                    summary = entry.get("summary", "") or entry.get("description", "")
                    link = entry.get("link")
                    date = entry.get("published") or entry.get("updated") or entry.get("created")
                    alert_type = "Officiel" if self._is_official_source(source_name) else "Veille"
                    self._append_alert(
                        self._make_alert(
                            stream=stream,
                            source=source,
                            title=title,
                            link=link,
                            summary=summary,
                            date=date,
                            alert_type=alert_type,
                        )
                    )

                self._register_source_result(source_name, True)
            except Exception as exc:
                logging.warning(f"Le flux {source_name} a échoué : {exc}")
                self._register_source_result(source_name, False, str(exc))

    def fetch_anthropic_news(self, source):
        source_name = source.get("name", "Anthropic News")
        try:
            response = self.session.get(source["url"], timeout=self.request_timeout)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")

            items = []
            for anchor in soup.select('a[href^="/news/"]'):
                href = anchor.get("href")
                title_node = anchor.find(["h2", "h3", "h4", "h5"])
                title = title_node.get_text(" ", strip=True) if title_node else self._slug_to_title(href.rstrip("/").split("/")[-1])
                summary_node = anchor.find("p")
                summary = summary_node.get_text(" ", strip=True) if summary_node else ""
                date_node = anchor.find("time")
                date = date_node.get("datetime") or date_node.get_text(" ", strip=True) if date_node else None
                if href and title:
                    items.append((href, title, summary, date))

            seen = set()
            for href, title, summary, date in items:
                if href in seen:
                    continue
                seen.add(href)
                self._append_alert(
                    self._make_alert(
                        stream="ai",
                        source=source,
                        title=title,
                        link=urljoin(source["url"], href),
                        summary=summary,
                        date=date,
                        alert_type="Officiel",
                    )
                )

            self._register_source_result(source_name, True)
        except Exception as exc:
            logging.warning(f"La source web {source_name} a échoué : {exc}")
            self._register_source_result(source_name, False, str(exc))

    def fetch_openai_sitemap(self, source):
        source_name = source.get("name", "OpenAI Updates")
        cutoff = self.run_started_at - timedelta(days=self.sitemap_days_window)
        include_path_fragments = ("/index/", "/research/")
        important_slug_terms = (
            "gpt",
            "chatgpt",
            "codex",
            "sora",
            "api",
            "reasoning",
            "model",
            "models",
            "agent",
            "memory",
            "safety",
            "research",
        )

        try:
            response = self.session.get(source["url"], timeout=self.request_timeout)
            response.raise_for_status()
            root = ET.fromstring(response.text)
            namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

            for url_node in root.findall(".//sm:url", namespace):
                loc_node = url_node.find("sm:loc", namespace)
                lastmod_node = url_node.find("sm:lastmod", namespace)
                if loc_node is None:
                    continue

                loc = loc_node.text
                lastmod = self._parse_datetime(lastmod_node.text if lastmod_node is not None else None)
                parsed = urlparse(loc)
                slug = parsed.path.rstrip("/").split("/")[-1]
                normalized_path = parsed.path.rstrip("/")
                if not any(fragment in parsed.path for fragment in include_path_fragments):
                    continue
                if normalized_path in {"", "/research", "/news"}:
                    continue
                if lastmod and lastmod < cutoff:
                    continue
                if not any(term in slug.lower() for term in important_slug_terms):
                    continue

                title = self._slug_to_title(slug)
                summary = "Mise à jour officielle détectée sur le site OpenAI."
                self._append_alert(
                    self._make_alert(
                        stream="ai",
                        source=source,
                        title=title,
                        link=loc,
                        summary=summary,
                        date=lastmod,
                        alert_type="Officiel",
                    )
                )

            self._register_source_result(source_name, True)
        except Exception as exc:
            logging.warning(f"Le sitemap {source_name} a échoué : {exc}")
            self._register_source_result(source_name, False, str(exc))

    def fetch_nist_cve(self):
        if not self.enable_nvd:
            return

    def _is_duplicate_alert(self, candidate, existing):
        if candidate["stream"] != existing["stream"]:
            return False
        if candidate["id"] == existing["id"]:
            return True

        left = self._normalize_title(candidate.get("title"))
        right = self._normalize_title(existing.get("title"))
        if left == right:
            return True
        if not left or not right:
            return False
        return SequenceMatcher(None, left, right).ratio() >= self.dedupe_similarity_threshold

    def _detect_company(self, alert):
        haystack = f"{alert.get('source', '')} {alert.get('title', '')} {alert.get('summary', '')}".lower()
        if any(alias in haystack for alias in self.ai_company_aliases["OpenAI"]):
            return "OpenAI"
        if any(alias in haystack for alias in self.ai_company_aliases["Anthropic"]):
            return "Anthropic"
        return None

    def _diversify_ai_alerts(self, alerts):
        selected = []
        for company in self.preferences.get("companies", []):
            company_candidates = [alert for alert in alerts if self._detect_company(alert) == company and alert not in selected]
            if not company_candidates:
                continue

            official_candidates = [alert for alert in company_candidates if self._is_official_source(alert.get("source", ""))]
            if official_candidates:
                selected.append(official_candidates[0])
                continue

            for alert in alerts:
                if alert in selected:
                    continue
                if self._detect_company(alert) == company:
                    selected.append(alert)
                    break

        for alert in alerts:
            if alert in selected:
                continue
            selected.append(alert)
            if len(selected) >= self.max_items_per_stream:
                break

        return selected[: self.max_items_per_stream]

    def _finalize_alerts(self):
        sorted_alerts = sorted(
            self.new_data["alerts"],
            key=lambda alert: (
                0 if self._is_official_source(alert.get("source", "")) else 1,
                -float(alert.get("score", 0)),
                self._parse_datetime(alert.get("date")) or datetime.min.replace(tzinfo=timezone.utc),
            ),
        )

        deduplicated = []
        for alert in sorted_alerts:
            if any(self._is_duplicate_alert(alert, existing) for existing in deduplicated):
                continue
            deduplicated.append(alert)

        deduplicated.sort(
            key=lambda alert: (
                0 if alert.get("stream") == "cyber" else 1,
                -float(alert.get("score", 0)),
                self._parse_datetime(alert.get("date")) or datetime.min.replace(tzinfo=timezone.utc),
            )
        )

        cyber_alerts = [alert for alert in deduplicated if alert.get("stream") == "cyber"]
        ai_alerts = [alert for alert in deduplicated if alert.get("stream") == "ai"]

        cyber_alerts = cyber_alerts[: self.max_items_per_stream]
        ai_alerts = self._diversify_ai_alerts(ai_alerts)

        self.new_data["streams"] = {"cyber": cyber_alerts, "ai": ai_alerts}
        self.new_data["alerts"] = cyber_alerts + ai_alerts
        self.new_data["summary"] = {
            "total_alerts": len(self.new_data["alerts"]),
            "cyber_alerts": len(cyber_alerts),
            "ai_alerts": len(ai_alerts),
            "priority_alerts": sum(1 for alert in self.new_data["alerts"] if alert.get("match")),
            "sources_count": len({alert.get("source") for alert in self.new_data["alerts"]}),
        }

    def has_new_data(self):
        old_ids = {alert["id"] for alert in self.current_data.get("alerts", [])}
        new_ids = {alert["id"] for alert in self.new_data["alerts"]}
        return not new_ids.issubset(old_ids)

    def save_data(self):
        try:
            with open(self.data_path, "w", encoding="utf-8") as file_obj:
                json.dump(self.new_data, file_obj, ensure_ascii=False, indent=4)
            logging.info("J'ai sauvegardé les nouvelles données JSON.")

            today_str = self.run_started_at.strftime("%Y-%m-%d")
            data_dir = os.path.dirname(self.data_path)
            daily_path = os.path.join(data_dir, f"{today_str}.json")
            with open(daily_path, "w", encoding="utf-8") as file_obj:
                json.dump(self.new_data, file_obj, ensure_ascii=False, indent=4)

            index_path = os.path.join(data_dir, "index.json")
            index_data = []
            if os.path.exists(index_path):
                try:
                    with open(index_path, "r", encoding="utf-8") as file_obj:
                        index_data = json.load(file_obj)
                except Exception:
                    index_data = []

            index_data = [item for item in index_data if item.get("date") != today_str]
            summary = self.new_data.get("summary", {})
            index_data.append(
                {
                    "date": today_str,
                    "file": f"{today_str}.json",
                    "total_alerts": summary.get("total_alerts", 0),
                    "cyber_alerts": summary.get("cyber_alerts", 0),
                    "ai_alerts": summary.get("ai_alerts", 0),
                    "priority_alerts": summary.get("priority_alerts", 0),
                    # Compatibilité avec les anciennes vues.
                    "total_cves": summary.get("total_alerts", 0),
                    "critical_cves": summary.get("priority_alerts", 0),
                }
            )
            index_data = sorted(index_data, key=lambda item: item["date"])

            with open(index_path, "w", encoding="utf-8") as file_obj:
                json.dump(index_data, file_obj, ensure_ascii=False, indent=4)
            logging.info("J'ai mis à jour l'historique.")
        except Exception as exc:
            logging.error(f"Je n'ai pas pu sauvegarder les fichiers JSON : {exc}")

    def update_readme(self):
        try:
            summary = self.new_data.get("summary", {})
            date_str = self.run_started_at.astimezone(timezone.utc).strftime("%d/%m/%Y à %H:%M UTC")
            stats_block = (
                "<!-- STATS_START -->\n"
                f"**Dernière mise à jour :** {date_str}  \n"
                f"**Alertes Cyber retenues :** {summary.get('cyber_alerts', 0)}  \n"
                f"**Alertes IA retenues :** {summary.get('ai_alerts', 0)}  \n"
                f"**Alertes prioritaires :** {summary.get('priority_alerts', 0)}  \n"
                "<!-- STATS_END -->"
            )

            if os.path.exists(self.readme_path):
                with open(self.readme_path, "r", encoding="utf-8") as file_obj:
                    content = file_obj.read()

                if "<!-- STATS_START -->" in content:
                    new_content = re.sub(
                        r"<!-- STATS_START -->.*<!-- STATS_END -->",
                        stats_block,
                        content,
                        flags=re.DOTALL,
                    )
                else:
                    new_content = content + "\n\n" + stats_block

                with open(self.readme_path, "w", encoding="utf-8") as file_obj:
                    file_obj.write(new_content)
            else:
                with open(self.readme_path, "w", encoding="utf-8") as file_obj:
                    file_obj.write(f"# Cyber Threat Intelligence Dashboard\n\n{stats_block}\n")
            logging.info("J'ai mis à jour le README.")
        except Exception as exc:
            logging.error(f"Erreur pendant la mise à jour du README : {exc}")

    def run(self):
        logging.info("Je lance la veille cyber + IA ciblée.")

        self.fetch_rss_sources(self.sources.get("cyber_rss", []), stream="cyber")
        self.fetch_rss_sources(self.sources.get("ai_rss", []), stream="ai")

        for source in self.sources.get("ai_web", []):
            strategy = source.get("strategy")
            if strategy == "anthropic_news":
                self.fetch_anthropic_news(source)

        for source in self.sources.get("ai_sitemaps", []):
            strategy = source.get("strategy")
            if strategy == "openai_sitemap":
                self.fetch_openai_sitemap(source)

        self.fetch_nist_cve()
        self._finalize_alerts()

        if self.source_attempts == 0:
            raise RuntimeError("Aucune source n'est configurée pour la collecte.")
        if not self.successful_sources:
            raise RuntimeError("Toutes les sources ont échoué. Snapshot annulé pour préserver les données existantes.")
        if not self.new_data["alerts"]:
            raise RuntimeError("La collecte n'a produit aucune alerte utile. Snapshot annulé.")

        if self.failed_sources:
            logging.warning(f"Sources en échec pendant cette exécution : {self.failed_sources}")

        if self.force_daily_snapshot or self.has_new_data():
            self.save_data()
            self.update_readme()
        else:
            logging.info("Aucun changement détecté et snapshot quotidien désactivé. Je ne sauvegarde rien.")


if __name__ == "__main__":
    ThreatIntelFetcher().run()
