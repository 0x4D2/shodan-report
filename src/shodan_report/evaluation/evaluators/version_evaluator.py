# src/shodan_report/evaluation/evaluators/version_evaluator.py
from typing import Optional, List, Dict, Any
import re

from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk


class VersionEvaluator(ServiceEvaluator):
    """Add-on Evaluator für Version-Risiko-Bewertung"""

    # Version-Datenbank (könnte auch aus externer Quelle kommen)
    VERSION_CHECKS = {
        # MySQL
        "mysql": {
            "secure_min": "8.0.0",
            "critical_max": "5.7.0",
            "latest": "8.0.40",
            "eol_versions": ["5.5", "5.6", "5.7", "8.0.33"],
        },
        # PostgreSQL
        "postgresql": {
            "secure_min": "12.0",
            "critical_max": "9.6.0",
            "latest": "16.3",
            "eol_versions": ["9.5", "9.6", "10", "11"],
        },
        # Apache
        "apache": {
            "secure_min": "2.4.50",
            "critical_max": "2.4.49",
            "latest": "2.4.59",
            "eol_versions": ["2.2", "2.0"],
        },
        # Nginx
        "nginx": {
            "secure_min": "1.20.0",
            "critical_max": "1.18.0",
            "latest": "1.25.4",
            "eol_versions": ["1.16", "1.14"],
        },
        # OpenSSH
        "openssh": {
            "secure_min": "8.0",
            "critical_max": "7.4",
            "latest": "9.8",
            "eol_versions": ["7.3", "7.2", "7.1"],
        },
        # Redis
        "redis": {
            "secure_min": "6.0.0",
            "critical_max": "5.0.0",
            "latest": "7.2.4",
            "eol_versions": ["4.0", "5.0"],
        },
        # MongoDB
        "mongodb": {
            "secure_min": "4.4.0",
            "critical_max": "3.6.0",
            "latest": "7.0.6",
            "eol_versions": ["3.2", "3.4", "3.6"],
        },
        # PHP
        "php": {
            "secure_min": "8.1.0",
            "critical_max": "7.4.0",
            "latest": "8.3.12",
            "eol_versions": ["5.6", "7.0", "7.1", "7.2", "7.3", "7.4"],
        },
    }

    def __init__(self, config):
        super().__init__(config)
        # Lazy import von packaging um Abhängigkeit optional zu machen
        self._packaging_available = self._check_packaging_available()

    def applies_to(self, service: Service) -> bool:
        """Gilt für Services mit Version-Information"""
        return bool(service.version and service.product)

    def evaluate(self, service: Service) -> ServiceRisk:
        """Bewertet Version-Risiko"""
        if not self.applies_to(service):
            return ServiceRisk(risk_score=0)

        product_key = self._normalize_product_name(service.product)
        version_info = self._analyze_version(product_key, service.version, service)

        return ServiceRisk(
            risk_score=version_info["risk_score"],
            message=version_info["message"],
            is_critical=version_info["is_critical"],
            should_exclude_from_critical=False,
            recommendations=version_info["recommendations"],
        )

    def _normalize_product_name(self, product: str) -> str:
        """Normalisiert Produktnamen für Lookup"""
        if not product:
            return ""

        product_lower = product.lower()

        # Mapping von verschiedenen Namen zu unseren Keys
        name_mapping = {
            "mysql": ["mysql", "mariadb"],
            "postgresql": ["postgresql", "postgres"],
            "apache": ["apache", "httpd", "apache http server"],
            "nginx": ["nginx", "nginx/"],
            "openssh": ["openssh", "ssh", "opensshd"],
            "redis": ["redis"],
            "mongodb": ["mongodb", "mongo"],
            "php": ["php"],
        }

        for key, names in name_mapping.items():
            if any(name in product_lower for name in names):
                return key

        return product_lower

    def _analyze_version(
        self, product: str, version: str, service: Service
    ) -> Dict[str, Any]:
        """Analysiert Version auf Sicherheitsrisiken"""
        if product not in self.VERSION_CHECKS:
            # Fallback für unbekannte Produkte
            return self._analyze_unknown_product(service)

        check_data = self.VERSION_CHECKS[product]

        # Versuch: Produkt-spezifische Version extrahieren (z.B. 'nginx/1.18.0' oder 'Server: nginx/1.18.0').
        # Wichtig: Vermeide das unerwünschte Erfassen führender HTTP-Versionen
        # wie '1.1 200 OK Server: nginx ...' — wir akzeptieren nur Versionen,
        # die direkt in Verbindung mit dem Produktnamen stehen.
        normalized_version = ""
        product_pattern = re.escape(product)
        # 1) Produkt gefolgt von Version (nginx/1.18.0, nginx 1.18.0)
        m = re.search(rf"(?:{product_pattern})[/\s:]+(\d+(?:\.\d+)*)", version, re.I)
        if m:
            normalized_version = m.group(1)
        else:
            # 2) 'Server: nginx/1.18.0' ähnliche Formen
            m2 = re.search(rf"Server[:\s]+(?:{product_pattern})[/\s:]*(\d+(?:\.\d+)*)", version, re.I)
            if m2:
                normalized_version = m2.group(1)

        # Fallback: wenn keine produktbezogene Version gefunden wurde,
        # akzeptiere reine numerische Versionstrings wie '5.7.33', aber
        # ignoriere komplexe Banner wie '1.1 200 OK Server: nginx ...'.
        if not normalized_version:
            if re.match(r"^\s*\d+(?:\.\d+)*\s*$", version):
                normalized_version = self._normalize_version(version)
            else:
                normalized_version = ""
        if not normalized_version:
            return {
                "risk_score": 0,
                "message": "",
                "is_critical": False,
                "recommendations": [],
            }

        # Prüfe auf EOL (End of Life)
        is_eol = self._is_version_eol(
            product, normalized_version, check_data["eol_versions"]
        )

        # Prüfe auf bekannte kritische Versionen
        is_critical_version = self._compare_versions(
            normalized_version, "<=", check_data["critical_max"]
        )

        # Prüfe ob veraltet (nicht mehr empfohlen)
        is_outdated = self._compare_versions(
            normalized_version, "<", check_data["secure_min"]
        )

        # Risiko-Score berechnen
        risk_score = 0
        message = ""

        if is_eol:
            risk_score = 5
            message = f"EOL-Version: {service.product} {version}"
        elif is_critical_version:
            risk_score = 4
            message = f"Auffällige Version (OSINT-Indiz): {service.product} {version}"
        elif is_outdated:
            risk_score = 2
            message = f"Veraltete Version: {service.product} {version}"
        else:
            # Aktuelle Version
            risk_score = 1
            message = f"Aktuelle Version: {service.product} {version}"

        # Empfehlungen
        recommendations = []
        if risk_score >= 2:  # Nur bei veralteten/kritischen Versionen
            recommendations.append(f"Update auf {check_data['latest']} durchführen")
            if risk_score >= 4:
                recommendations.insert(
                    0, f"SOFORT: {service.product} auf aktuelle Version updaten"
                )
            if is_eol:
                recommendations.append(
                    f"{service.product} Version {version} ist End-of-Life"
                )

        return {
            "risk_score": risk_score,
            "message": message,
            "is_critical": (risk_score >= 4),  # Kritisch ab Score 4
            "recommendations": recommendations,
        }

    def _analyze_unknown_product(self, service: Service) -> Dict[str, Any]:
        """Analyse für unbekannte Produkte (Fallback)."""
        # Einfache Heuristik: Prüfe ob Version sehr alt aussieht
        version = service.version or ""

        # Extrahiere Jahreszahl aus Version (z.B. 2019, 2020)
        year_match = re.search(r"(\d{4})", version)
        if year_match:
            year = int(year_match.group(1))
            if year < 2020:
                return {
                    "risk_score": 3,
                    "message": f"Möglicherweise veraltet: {service.product} {version}",
                    "is_critical": False,
                    "recommendations": [
                        f"{service.product} auf aktuelle Version prüfen"
                    ],
                }

        return {
            "risk_score": 0,
            "message": "",
            "is_critical": False,
            "recommendations": [],
        }

    def _normalize_version(self, version: str) -> str:
        """Normalisiert Version-String für Vergleich"""
        if not version:
            return ""

        # Entferne alles außer Zahlen und Punkte am Anfang
        # Behandle Fälle wie "2.4.49-mod", "7.6p1", "v1.18.0"

        # 1. Entferne führende Buchstaben (v1.0 -> 1.0)
        version = re.sub(r"^[a-zA-Z]+", "", version)

        # 2. Extrahiere Zahlen und Punkte am Anfang
        match = re.search(r"^(\d+(?:\.\d+)*)", version)
        if match:
            normalized = match.group(1)
        else:
            normalized = version

        # 3. Stelle sicher, dass wir mindestens Major.Minor haben
        parts = normalized.split(".")
        if len(parts) < 2:
            if parts and parts[0]:
                return f"{parts[0]}.0"
            return ""

        return ".".join(parts[:3])  # Max. Major.Minor.Patch

    def _is_version_eol(
        self, product: str, version: str, eol_versions: List[str]
    ) -> bool:
        """Prüft ob Version End-of-Life ist"""
        for eol_version in eol_versions:
            if version.startswith(eol_version):
                return True
        return False

    def _compare_versions(self, version1: str, operator: str, version2: str) -> bool:
        """Vergleicht zwei Version-Strings"""
        try:
            if self._packaging_available:
                from packaging import version as pkg_version

                v1 = pkg_version.parse(version1)
                v2 = pkg_version.parse(version2)

                if operator == "<":
                    return v1 < v2
                elif operator == "<=":
                    return v1 <= v2
                elif operator == ">":
                    return v1 > v2
                elif operator == ">=":
                    return v1 >= v2
                elif operator == "==":
                    return v1 == v2
        except Exception:
            # Fallback auf einfache String-Vergleich
            pass

        # Fallback: Einfacher String-Vergleich
        try:
            if operator == "<":
                return version1 < version2
            elif operator == "<=":
                return version1 <= version2
            elif operator == ">":
                return version1 > version2
            elif operator == ">=":
                return version1 >= version2
            elif operator == "==":
                return version1 == version2
        except Exception:
            pass

        return False

    def _check_packaging_available(self) -> bool:
        """Prüft ob packaging Modul verfügbar ist."""
        try:
            import packaging.version

            return True
        except ImportError:
            return False

    # Öffentliche Methoden für Tests
    def calculate_version_risk(self, product: str, version: str) -> int:
        """Öffentliche Methode für Tests."""
        product_key = self._normalize_product_name(product)
        version_info = self._analyze_version(
            product_key,
            version,
            Service(port=0, transport="tcp", product=product, version=version),
        )
        return version_info["risk_score"]


def create_version_evaluator(config):
    """Factory-Funktion zur Erstellung eines VersionEvaluators."""
    return VersionEvaluator(config)
