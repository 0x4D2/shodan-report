from typing import List, Dict
from dataclasses import dataclass
from enum import Enum


class CVESeverity(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class CVE:
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


def convert_to_cve_objects(vulnerabilities: List) -> List[CVE]:
    """Konvertiert Rohdaten zu `CVE`-Objekten."""
    cves: List[CVE] = []

    for vuln in vulnerabilities:
        if isinstance(vuln, dict):
            cve_id = vuln.get("id", "UNKNOWN-CVE")
            cvss = vuln.get("cvss", 0.0)
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = 0.0

            cves.append(
                CVE(
                    id=cve_id,
                    cvss=cvss,
                    summary=vuln.get("summary", ""),
                    verified=vuln.get("verified", False),
                    products=vuln.get("products", []),
                )
            )
        elif isinstance(vuln, str):
            cves.append(CVE(id=vuln, cvss=0.0))

    return cves


def count_cves_by_severity(cves: List[CVE]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(cves)}

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


def generate_cve_message(cve_counts: Dict, service) -> str:
    """Generiert eine lesbare CVE-Nachricht für ein Service.

    Kehrt dieselbe Ausgabe zurück wie vorher im Evaluator, aber ist
    jetzt ein pure helper, damit Präsentation testbar und wiederverwendbar ist.
    """
    if cve_counts.get("total", 0) == 0:
        return ""

    product_info = ""
    if getattr(service, "product", None):
        product_info = f" ({service.product}"
        if getattr(service, "version", None):
            product_info += f" {service.version}"
        product_info += ")"

    if cve_counts.get("critical", 0) > 0:
        return f"{cve_counts['critical']} kritische CVEs{product_info}"
    elif cve_counts.get("high", 0) > 0:
        return f"{cve_counts['high']} hochriskante CVEs{product_info}"
    elif cve_counts.get("total", 0) > 0:
        return f"{cve_counts['total']} CVEs identifiziert{product_info}"

    return ""
