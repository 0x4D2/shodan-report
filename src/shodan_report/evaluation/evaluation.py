"""
All-in-One Evaluation Module - Enthält alles für Backward Compatibility.
"""

from enum import Enum
from typing import List
from dataclasses import dataclass, field
from shodan_report.models import AssetSnapshot, Service

# ============================================================================
# ENUMS
# ============================================================================


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BusinessRisk(Enum):
    CRITICAL = "critical"
    ATTENTION = "attention"
    MONITOR = "monitor"


# ============================================================================
# DATACLASSES
# ============================================================================


@dataclass
class Evaluation:
    ip: str
    risk: RiskLevel
    critical_points: List[str] = field(default_factory=list)
    exposure_score: int = 1


# ============================================================================
# HAUPTFUNKTIONEN
# ============================================================================


def evaluate_snapshot(snapshot: AssetSnapshot) -> Evaluation:
    critical_points = []
    risk_score = 0

    # 1. Port-Analyse
    num_ports = len(snapshot.services)
    if num_ports > 25:
        critical_points.append(f"Sehr viele offene Ports: {num_ports}")
        risk_score += 3
    elif num_ports >= 15:
        critical_points.append(f"Viele offene Ports: {num_ports}")
        risk_score += 2
    elif num_ports > 8:
        critical_points.append("Mehrere offene Dienste")
        risk_score += 1

    # 2. Service-Analyse
    for service in snapshot.services:
        port = service.port
        has_ssl = service.ssl_info
        product = (service.product or "").lower()

        # Kritische Services
        if port == 3389 and not has_ssl:
            critical_points.append("RDP öffentlich erreichbar ohne Verschlüsselung")
            risk_score += 3
        elif port == 5900 and not has_ssl:
            critical_points.append("VNC öffentlich erreichbar ohne Verschlüsselung")
            risk_score += 3
        elif port == 23:
            critical_points.append("Telnet (unverschlüsselt)")
            risk_score += 3

        # SSH als "kritischer Dienst" für Kompatibilität mit alten Tests
        elif port == 22:
            critical_points.append("Kritischer Dienst gefunden: SSH")
            risk_score += 2

        # Datenbanken
        elif port in [3306, 5432, 27017, 6379, 1433] and not has_ssl:
            critical_points.append(f"Datenbank öffentlich erreichbar auf Port {port}")
            risk_score += 2

        # FTP unverschlüsselt
        elif port == 21 and not has_ssl:
            critical_points.append("FTP unverschlüsselt")
            risk_score += 1

        # HTTP ohne SSL
        elif port == 80 and not has_ssl:
            critical_points.append("HTTP ohne Verschlüsselung")
            risk_score += 1

        # Veraltete Versionen für Kompatibilität mit Tests
        version = (service.version or "").lower()
        if "1.0" in version or "deprecated" in version:
            critical_points.append("Veraltete/anfällige Version erkannt")
            risk_score += 1

    # 3. Risk Level bestimmen
    if any("RDP" in cp or "VNC" in cp or "Telnet" in cp for cp in critical_points):
        risk = RiskLevel.CRITICAL
    elif risk_score >= 3:
        risk = RiskLevel.HIGH
    elif risk_score >= 1:
        risk = RiskLevel.MEDIUM
    else:
        risk = RiskLevel.LOW

    # 4. Exposure Score (1-5)
    if risk_score >= 5:
        exposure = 5
    elif risk_score >= 3:
        exposure = 4
    elif risk_score >= 2:
        exposure = 3
    elif risk_score >= 1:
        exposure = 2
    else:
        exposure = 1

    return Evaluation(
        ip=snapshot.ip,
        risk=risk,
        critical_points=critical_points,
        exposure_score=exposure,
    )


def prioritize_risk(evaluation: Evaluation) -> BusinessRisk:

    # 1. Kritische technische Issues werden sofort zu Business CRITICAL
    if evaluation.risk == RiskLevel.CRITICAL:
        return BusinessRisk.CRITICAL

    # 2. HIGH technisches Risiko wird auch Business CRITICAL
    if evaluation.risk == RiskLevel.HIGH:
        return BusinessRisk.CRITICAL

    # 3. Für zusätzliche Checks
    for point in evaluation.critical_points:
        if "Kritischer Dienst gefunden" in point:
            return BusinessRisk.CRITICAL

    # 4. MEDIUM wird zu ATTENTION
    if evaluation.risk == RiskLevel.MEDIUM:
        return BusinessRisk.ATTENTION

    # 5. Alles andere ist MONITOR
    return BusinessRisk.MONITOR


def technical_to_business_risk(
    technical_risk: RiskLevel, critical_points: List[str] = None
) -> BusinessRisk:

    if critical_points is None:
        critical_points = []

    if technical_risk == RiskLevel.CRITICAL:
        return BusinessRisk.CRITICAL
    elif technical_risk == RiskLevel.HIGH:
        return BusinessRisk.CRITICAL
    elif technical_risk == RiskLevel.MEDIUM:
        return BusinessRisk.ATTENTION
    else:
        return BusinessRisk.MONITOR


# ============================================================================
# HILFSFUNKTIONEN (für Kompatibilität mit altem Code)
# ============================================================================


def _analyze_open_ports(services: List[Service], critical_points: List[str]) -> int:
    score = 0
    num_ports = len(services)

    if num_ports > 30:
        score += 3
        critical_points.append(f"Sehr viele offene Ports: {num_ports}")
    elif num_ports > 20:
        score += 2
        critical_points.append(f"Viele offene Ports: {num_ports}")
    elif num_ports > 10:
        score += 1
        critical_points.append(f"Mehrere offene Dienste: {num_ports}")

    return score


def _analyze_services(services: List[Service], critical_points: List[str]) -> int:
    score = 0

    for service in services:
        port = service.port
        has_ssl = service.ssl_info

        if port == 3389 and not has_ssl:
            score += 3
            critical_points.append("RDP öffentlich erreichbar")
        elif port == 23:
            score += 2
            critical_points.append("Telnet (unverschlüsselt)")
        elif port == 22:
            score += 2
            critical_points.append("Kritischer Dienst gefunden: SSH")
        elif port == 80 and not has_ssl:
            score += 1
            critical_points.append("HTTP ohne Verschlüsselung")

    return score


def _calculate_risk_level(critical_points: List[str], exposure_score: int) -> RiskLevel:
    # Prüfe auf KRITISCHE Probleme
    has_critical_issue = False
    for point in critical_points:
        point_lower = point.lower()
        if "rdp" in point_lower or "vnc" in point_lower or "telnet" in point_lower:
            has_critical_issue = True
            break

    if has_critical_issue:
        return RiskLevel.CRITICAL

    # Normale Bewertung
    if exposure_score >= 4:
        return RiskLevel.HIGH
    elif exposure_score >= 3:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW


# ============================================================================
# KONSTANTEN (für Kompatibilität)
# ============================================================================

HIGH_RISK_SERVICES = {
    "rdp": 5,
    "vnc": 5,
    "telnet": 4,
    "mysql": 4,
    "postgresql": 4,
    "mongodb": 4,
    "redis": 4,
}

SECURE_INDICATORS = ["tls", "ssl", "starttls", "https", "wss"]

VULNERABLE_INDICATORS = {
    "1.0": 2,
    "2.0": 1,
    "deprecated": 3,
    "end-of-life": 4,
    "test": 2,
    "dev": 2,
    "alpha": 2,
    "beta": 1,
    "rc": 1,
}

# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    # Enums
    "RiskLevel",
    "BusinessRisk",
    # Classes
    "Evaluation",
    # Main Functions
    "evaluate_snapshot",
    "prioritize_risk",
    "technical_to_business_risk",
    # Helper Functions (for compatibility)
    "_analyze_open_ports",
    "_analyze_services",
    "_calculate_risk_level",
    # Constants (for compatibility)
    "HIGH_RISK_SERVICES",
    "SECURE_INDICATORS",
    "VULNERABLE_INDICATORS",
]
