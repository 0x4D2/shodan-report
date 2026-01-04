from dataclasses import dataclass
from enum import Enum
from typing import List, ClassVar
from dataclasses import field
from shodan_report.models import AssetSnapshot

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

@dataclass
class Evaluation:
    ip: str
    risk: RiskLevel
    critical_points: List[str] = field(default_factory=list)
    
    HIGH_RISK_INDICATORS: ClassVar[List[str]] = ["Viele offene Dienste", "Kritischer Dienst"]
    CRITICAL_SERVICES: ClassVar[List[str]] = ["ssh", "rdp"]

    # Platzhalter für veraltete Versionen, später echte CVE-Bewertung
    VULNERABLE_INDICATORS: ClassVar[List[str]] = ["1.0", "vulnerable"]


def evaluate_snapshot(snapshot: AssetSnapshot) -> Evaluation:
    critical_points = []
    
    _analyze_open_ports(snapshot.services, critical_points)
    _analyze_services(snapshot.services, critical_points)
    
    risk = _calculate_risk_level(critical_points)
    
    return Evaluation(
        ip=snapshot.ip,
        risk=risk,
        critical_points=critical_points
    )

def _analyze_open_ports(services: List, critical_points: List[str]) -> None:
    num_ports = len(services)
    
    if num_ports > 10:
        critical_points.append(f"Viele offene Dienste: {num_ports}")
    elif num_ports >= 5:
        critical_points.append(f"Mehrere offene Dienste: {num_ports}")

def _analyze_services(services: List, critical_points: List[str]) -> None:
    for service in services:
        # Sicherstellen, dass product nicht None ist sonst crash bei lower()
        product_name = service.product.lower() if service.product else None

        if product_name and product_name in Evaluation.CRITICAL_SERVICES:
            critical_points.append(
                f"Kritischer Dienst gefunden: {service.product} auf Port {service.port}"
            )
        
        if service.version:
            version_lower = service.version.lower()
            if any(indicator in version_lower for indicator in Evaluation.VULNERABLE_INDICATORS):
                critical_points.append(
                    f"Veraltete/anfällige Version: {service.product or 'unbekannt'} "
                    f"Version {service.version} auf Port {service.port}"
                )

def _calculate_risk_level(critical_points: List[str]) -> RiskLevel:
    if not critical_points:
        return RiskLevel.LOW
    
    for point in critical_points:
        if any(indicator in point for indicator in Evaluation.HIGH_RISK_INDICATORS):
            return RiskLevel.HIGH
    
    return RiskLevel.MEDIUM