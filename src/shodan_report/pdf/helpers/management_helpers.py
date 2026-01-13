from typing import List, Dict, Any
from shodan_report.evaluation import Evaluation
from .evaluation_helpers import is_service_secure

def extract_first_sentence(text: str) -> str:
    """Extrahiere den ersten Satz aus einem Text für Management-Kernaussage."""
    import re
    match = re.search(r"[^.!?]+[.!?]", text.strip())
    if match:
        return match.group(0).strip()
    return text[:100].strip() + ("..." if len(text) > 100 else "")

def generate_priority_insights(
    technical_json: Dict[str, Any],
    evaluation: Evaluation,
    business_risk: str
) -> List[str]:
    insights = []
    open_ports: List = technical_json.get("open_ports", [])

    if open_ports:
        insights.append(f"{len(open_ports)} öffentliche Dienste erreichbar")

    vulnerabilities = technical_json.get("vulnerabilities", [])
    critical_cves = sum(1 for v in vulnerabilities if isinstance(v, dict) and v.get("cvss", 0) >= 9.0)
    insights.append(f"{critical_cves} kritische Schwachstellen" if critical_cves else "Keine kritischen Schwachstellen")

    critical_count = len(evaluation.critical_points) if evaluation.critical_points else 0
    insecure_services = 0
    secure_indicators = ["ssh", "rdp", "https", "tls", "vpn"]
    for service in open_ports:
        if not is_service_secure(service, secure_indicators):
            insecure_services += 1

    if insecure_services > 0:
        insights.append(f"{critical_count + insecure_services} kritische Risikopunkte (inkl. unsicherer Dienste)")
    else:
        insights.append(f"{critical_count} kritische Risikopunkte")

    if str(business_risk).upper() in ["HIGH", "CRITICAL"]:
        insights.append("Erhöhter Handlungsbedarf")

    return insights[:4]

def generate_priority_recommendations(
    business_risk: str,
    technical_json: Dict[str, Any]
) -> List[str]:
    recommendations = []
    base_recommendations = {
        "CRITICAL": ["Sofortige Notfallmaßnahmen einleiten", "Kritische Dienste temporär isolieren"],
        "HIGH": ["Priorisierte Maßnahmen innerhalb von 7 Tagen", "Kritische Konfigurationen überprüfen"],
        "MEDIUM": ["Geplante Maßnahmen innerhalb von 30 Tagen", "Regelmäßige Sicherheitsscans etablieren"],
        "LOW": ["Keine sofortigen Notfallmaßnahmen erforderlich", "Kurzfristig: Einzelne Konfigurationen optimieren"]
    }
    recommendations.extend(base_recommendations.get(business_risk.upper(), [
        "Regelmäßige Überprüfung der Angriffsfläche",
        "Proaktive Schwachstellenscans etablieren"
    ])[:2])

    open_ports: List = technical_json.get("open_ports", [])
    for service in open_ports:
        port = service.port
        product = (service.product or "").lower() if service.product else ""
        if port == 22 and "ssh" in product:
            recommendations.append("SSH: Schlüsselbasierte Authentifizierung erzwingen")
        elif port == 3389 and "rdp" in product:
            recommendations.append("RDP: Netzwerk-Level-Authentifizierung aktivieren")

    return recommendations[:3]
