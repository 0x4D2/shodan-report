# src/shodan_report/evaluation/evaluators/cve_evaluator.py
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk


# 1. Kopiere die CVESeverity Enum aus cve_helpers.py
class CVESeverity(Enum):
    """CVSS Schweregrad-Kategorien."""

    NONE = 0  # 0.0
    LOW = 1  # 0.1 - 3.9
    MEDIUM = 2  # 4.0 - 6.9
    HIGH = 3  # 7.0 - 8.9
    CRITICAL = 4  # 9.0 - 10.0


# 2. Kopiere die CVE Dataclass aus cve_helpers.py
@dataclass
class CVE:
    """Dataclass für CVE-Informationen."""

    id: str
    cvss: float
    summary: str = ""
    verified: bool = False
    products: List[str] = None
    exploit_available: bool = False

    def __post_init__(self):
        if self.products is None:
            self.products = []

    @property
    def severity(self) -> CVESeverity:
        """Bestimmt Schweregrad basierend auf CVSS Score."""
        if self.cvss >= 9.0:
            return CVESeverity.CRITICAL
        elif self.cvss >= 7.0:
            return CVESeverity.HIGH
        elif self.cvss >= 4.0:
            return CVESeverity.MEDIUM
        elif self.cvss > 0:
            return CVESeverity.LOW
        else:
            return CVESeverity.NONE

    @property
    def is_critical(self) -> bool:
        """Prüft ob CVE als kritisch gilt (CVSS >= 7.0)."""
        return self.cvss >= 7.0


# 3. Erstelle den CVEEvaluator
class CVEEvaluator(ServiceEvaluator):
    """Add-on Evaluator für CVE-Bewertung - gilt für alle Services mit CVEs"""

    def applies_to(self, service: Service) -> bool:
        """Gilt für Services mit CVE-Daten in vulnerabilities ODER raw['vulns']"""
        # 1. Prüfe service.vulnerabilities
        if service.vulnerabilities:
            return True

        # 2. Prüfe raw['vulns'] (Shodan speichert CVEs oft hier)
        if hasattr(service, "raw") and service.raw:
            vulns = service.raw.get("vulns", [])
            if vulns:
                return True

        # 3. Prüfe andere mögliche Felder
        if hasattr(service, "raw") and service.raw:
            # Shodan kann CVEs auch anders speichern
            for key in ["vulnerabilities", "cves", "cve_ids"]:
                if key in service.raw and service.raw[key]:
                    return True

        return False

    def evaluate(self, service: Service) -> ServiceRisk:
        """Berechnet zusätzliches Risiko durch CVEs und generiert detaillierte critical_points"""
        if not service.vulnerabilities:
            return ServiceRisk(risk_score=0)

        # 1. Konvertiere Raw-CVEs zu CVE-Objekten
        cves = self._convert_to_cve_objects(service.vulnerabilities)

        # 2. Analysiere die CVEs
        cve_counts = self._count_cves_by_severity(cves)
        top_cves = self._get_top_cves(cves, limit=3)
        risk_score = self._calculate_cve_risk_score(cves)

        # 3. Generiere Message
        message = self._generate_cve_message(cve_counts, service)

        # 4. Generiere DETAILLIERTE CRITICAL POINTS
        critical_points = self._generate_detailed_critical_points(
            cve_counts, service, cves
        )

        # 5. Generiere Empfehlungen
        recommendations = self._generate_recommendations(cve_counts, top_cves)

        return ServiceRisk(
            risk_score=risk_score,
            message=message,
            is_critical=(cve_counts["critical"] > 0 or cve_counts["high"] >= 3),
            critical_points=critical_points,  # ⬅️ WICHTIG: Detaillierte critical_points!
            should_exclude_from_critical=False,
            recommendations=recommendations,
        )

    # NEUE HELPER-METHODE HINZUFÜGEN:
    def _generate_detailed_critical_points(
        self, cve_counts: Dict, service: Service, cves: List[CVE]
    ) -> List[str]:
        """Generiert detaillierte critical_points für CVE-Analyse."""
        critical_points = []

        if cve_counts["total"] == 0:
            return critical_points

        # Produkt- und Version-Info
        product_info = service.product or "Service"
        version_info = f" {service.version}" if service.version else ""

        # 1. Gesamt-CVE-Count
        if cve_counts["total"] > 0:
            critical_points.append(
                f"{product_info}{version_info} hat {cve_counts['total']} CVEs"
            )

        # 2. Kritische CVEs
        if cve_counts["critical"] > 0:
            critical_points.append(
                f"{cve_counts['critical']} kritische CVEs (CVSS ≥ 9.0)"
            )

        # 3. Hohe CVEs
        if cve_counts["high"] > 0:
            critical_points.append(
                f"{cve_counts['high']} hochriskante CVEs (CVSS 7.0-8.9)"
            )

        # 4. CVE-Jahres-Analyse
        if cves:
            cve_years = self._analyze_cve_years(cves)

            # Aktuelle Jahr-CVEs (z.B. 2025)
            current_year = "2025"
            if current_year in cve_years and cve_years[current_year] > 0:
                critical_points.append(
                    f"{cve_years[current_year]} kritische CVEs aus {current_year}"
                )

            # Zeige Top-Jahre
            if cve_years:
                top_years = sorted(cve_years.items(), key=lambda x: x[1], reverse=True)[
                    :2
                ]
                if len(top_years) > 0:
                    years_text = ", ".join(
                        f"{year}: {count}" for year, count in top_years
                    )
                    if len(cve_years) > 2:
                        years_text += f" (+{len(cve_years)-2} weitere Jahre)"
                    critical_points.append(f"CVEs aus Jahren: {years_text}")

        # 5. Top-CVE Details (wenn kritisch)
        if cves and (cve_counts["critical"] > 0 or cve_counts["high"] > 0):
            top_critical = sorted(cves, key=lambda x: x.cvss, reverse=True)[:1]
            if top_critical:
                top_cve = top_critical[0]
                if top_cve.cvss >= 9.0:
                    critical_points.append(
                        f"Kritischste CVE: {top_cve.id} (CVSS {top_cve.cvss})"
                    )

        return critical_points

    # ZUSÄTZLICHE HELPER-METHODE:
    def _analyze_cve_years(self, cves: List[CVE]) -> Dict[str, int]:
        """Analysiert CVE-Jahre und zählt pro Jahr."""
        cve_years = {}

        for cve in cves:
            if cve.id.startswith("CVE-"):
                # Extrahiere Jahr aus CVE-XXXX-YYYYY
                parts = cve.id.split("-")
                if len(parts) >= 2:
                    year = parts[1]
                    cve_years[year] = cve_years.get(year, 0) + 1

        return cve_years

    # 8. HELPER-METHODEN (kopiert/angepasst aus cve_helpers.py)

    def _convert_to_cve_objects(self, vulnerabilities: List) -> List[CVE]:
        """Konvertiert Raw CVE-Daten zu CVE-Objekten."""
        cves = []

        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                cve_id = vuln.get("id", "UNKNOWN-CVE")
                cvss = vuln.get("cvss", 0.0)

                # Shodan speichert CVEs manchmal anders
                if isinstance(cvss, str):
                    try:
                        cvss = float(cvss)
                    except ValueError:
                        cvss = 0.0

                cve = CVE(
                    id=cve_id,
                    cvss=cvss,
                    summary=vuln.get("summary", ""),
                    verified=vuln.get("verified", False),
                    products=vuln.get("products", []),
                )
                cves.append(cve)

            elif isinstance(vuln, str):
                # Einfache CVE-ID als String (z.B. "CVE-2025-50001")
                # Für Kompatibilität mit Tests: Standard-CVSS für reine ID-Strings = 0.0
                cvss_score = 0.0
                cve = CVE(id=vuln, cvss=cvss_score)
                cves.append(cve)

        return cves

    def _estimate_cvss_from_cve_id(self, cve_id: str) -> float:
        """Schätzt CVSS Score basierend auf CVE-ID."""
        # Standard: 7.0 für aktuelle CVEs (2024-2025), 5.0 für ältere
        if "2025" in cve_id or "2024" in cve_id:
            return 7.0  # Aktuelle CVEs sind oft kritisch
        elif "2023" in cve_id:
            return 5.0
        else:
            return 4.0

    def _count_cves_by_severity(self, cves: List[CVE]) -> Dict[str, int]:
        """Zählt CVEs nach Schweregrad (aus cve_helpers.py)."""
        counts = {
            "critical": 0,  # CVSS >= 9.0
            "high": 0,  # CVSS 7.0 - 8.9
            "medium": 0,  # CVSS 4.0 - 6.9
            "low": 0,  # CVSS 0.1 - 3.9
            "total": len(cves),
        }

        for cve in cves:
            if cve.cvss >= 9.0:
                counts["critical"] += 1
            elif cve.cvss >= 7.0:
                counts["high"] += 1
            elif cve.cvss >= 4.0:
                counts["medium"] += 1
            elif cve.cvss > 0:
                counts["low"] += 1

        return counts

    def _get_top_cves(self, cves: List[CVE], limit: int = 3) -> List[CVE]:
        """Gibt die wichtigsten CVEs zurück (aus cve_helpers.py)."""
        sorted_cves = sorted(cves, key=lambda x: x.cvss, reverse=True)
        return sorted_cves[:limit]

    def _calculate_cve_risk_score(self, cves: List[CVE]) -> int:
        """
        Berechnet Risiko-Score 0-5 basierend auf CVEs.
        Adaptiert aus calculate_cve_risk_score() in cve_helpers.py.
        """
        if not cves:
            return 0

        # Original-Logik aus cve_helpers.py (leicht angepasst für 0-5 Score)
        total_cves = len(cves)
        critical_cves = sum(1 for cve in cves if cve.cvss >= 9.0)
        high_cves = sum(1 for cve in cves if 7.0 <= cve.cvss < 9.0)

        # Risiko-Score 0-5 (statt 0-10 wie in cve_helpers.py)
        if critical_cves >= 3:
            return 5
        elif critical_cves >= 1:
            return 4
        elif high_cves >= 2:  # ⬅️ WICHTIG: Von 3 auf 2 ändern!
            return 4
        elif total_cves >= 10:
            return 3
        elif total_cves >= 5:
            return 2
        elif total_cves >= 1:
            return 1
        return 0

    def _generate_cve_message(self, cve_counts: Dict, service: Service) -> str:
        """Generiert eine lesbare CVE-Nachricht."""
        if cve_counts["total"] == 0:
            return ""

        product_info = ""
        if service.product:
            product_info = f" ({service.product}"
            if service.version:
                product_info += f" {service.version}"
            product_info += ")"

        if cve_counts["critical"] > 0:
            return f"{cve_counts['critical']} kritische CVEs{product_info}"
        elif cve_counts["high"] > 0:
            return f"{cve_counts['high']} hochriskante CVEs{product_info}"
        elif cve_counts["total"] > 0:
            return f"{cve_counts['total']} CVEs identifiziert{product_info}"

        return ""

    def _generate_recommendations(
        self, cve_counts: Dict, top_cves: List[CVE]
    ) -> List[str]:
        """Generiert Empfehlungen basierend auf CVE-Analyse."""
        recommendations = []

        if cve_counts["critical"] > 0:
            recommendations.append("Kritische CVEs umgehend patchen")

        if cve_counts["high"] >= 2:
            recommendations.append("Hochriskante CVEs prioritär behandeln")

        if cve_counts["total"] >= 5:
            recommendations.append("Sicherheitsupdates durchführen")

        # Spezifische Empfehlungen für Top-CVEs
        if top_cves:
            top_cve = top_cves[0]
            if top_cve.cvss >= 9.0:
                recommendations.append(
                    f"{top_cve.id}: Sofortiges Patching erforderlich"
                )

        return recommendations


# 9. Optional: Factory-Funktion für einfache Nutzung
def create_cve_evaluator(config):
    """Factory-Funktion zur Erstellung eines CVEEvaluators."""
    return CVEEvaluator(config)
