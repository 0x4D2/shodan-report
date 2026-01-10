from reportlab.platypus import Paragraph, Spacer
from typing import List, Dict, Any

from shodan_report.evaluation import RiskLevel, Evaluation

def create_management_section(
    elements: List,
    styles: Dict,
    management_text: str,
    technical_json: Dict[str, Any],
    evaluation: Evaluation,
    business_risk: str,
    config: Dict[str, Any] = None
) -> None:

    if isinstance(evaluation, dict):
        class EvaluationLike:
            def __init__(self, data):
                self.risk = data.get("risk", RiskLevel.MEDIUM)
                self.critical_points = data.get("critical_points", [])
                self.ip = data.get("ip", "")
                self.exposure_level = data.get("exposure_level", 2)
        
        evaluation = EvaluationLike(evaluation)
        
    config = config or {}
    
    # 1. ABSCHNITTSÜBERSCHRIFT
    elements.append(Paragraph("<b>1. Management-Zusammenfassung</b>", styles['heading2']))
    elements.append(Spacer(1, 12))
    
    # 2. GESAMTBEWERTUNG
    elements.append(Paragraph("<b>Gesamtbewertung der externen Angriffsfläche</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    
    # Evaluation hat: ip, risk (RiskLevel), critical_points (List[str])
    risk_level = evaluation.risk.value if hasattr(evaluation.risk, 'value') else str(evaluation.risk)
    
    exposure_level = _calculate_exposure_level(evaluation.risk, evaluation.critical_points)
    
    level_mapping = {
        1: "sehr niedrig",
        2: "niedrig", 
        3: "mittel",
        4: "hoch",
        5: "sehr hoch"
    }
    
    level_text = level_mapping.get(exposure_level, "niedrig–mittel")
    elements.append(Paragraph(
        f"Exposure-Level: <b>{exposure_level} von 5 ({level_text})</b>", 
        styles['normal']
    ))
    elements.append(Spacer(1, 8))
    
    # 3. BESCHREIBUNG aus management_text
    if management_text:
        lines = [line.strip() for line in management_text.splitlines() if line.strip()]
        for line in lines[:2]:  # Ersten 2 Zeilen nutzen
            elements.append(Paragraph(line, styles['normal']))
        elements.append(Spacer(1, 4))
    
    # 4. WICHTIGSTE ERKENNTNISSE
    elements.append(Paragraph("<b>Wichtigste Erkenntnisse</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    
    insights = _generate_insights(technical_json, evaluation, business_risk)
    
    for insight in insights:
        elements.append(Paragraph(f"• {insight}", styles['bullet']))
    
    elements.append(Spacer(1, 12))
    
    # 5. EMPFEHLUNGEN
    elements.append(Paragraph("<b>Empfehlung auf Management-Ebene</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    
    recommendations = _generate_recommendations(business_risk, technical_json, evaluation) 
    
    for rec in recommendations:
        elements.append(Paragraph(f"• {rec}", styles['bullet']))


def _calculate_exposure_level(risk: RiskLevel, critical_points: List[str]) -> int:
    # Basis-Level aus Risiko
    risk_to_exposure = {
        "low": 2,
        "medium": 3,
        "high": 4
    }
    
    risk_str = risk.value if hasattr(risk, 'value') else str(risk)
    base_level = risk_to_exposure.get(risk_str.lower(), 2)
    
    critical_count = len(critical_points) if critical_points else 0
    
    if critical_count >= 3:
        return min(base_level + 1, 5)  # Maximal 5
    elif critical_count == 0:
        return max(base_level - 1, 1)  # Minimal 1
    else:
        return base_level


def _generate_insights(
    technical_json: Dict[str, Any],
    evaluation: Evaluation,
    business_risk: str
) -> List[str]:
    insights = []
    
    # 1. Anzahl offener Ports
    open_ports = technical_json.get("open_ports", [])
    if open_ports:
        insights.append(f"{len(open_ports)} öffentliche Dienste erreichbar")
    
    exposure_level = _calculate_exposure_level(evaluation.risk, evaluation.critical_points)
    level_texts = {
        1: "sehr niedrig",
        2: "niedrig",
        3: "mittel",
        4: "hoch", 
        5: "sehr hoch"
    }
    level_text = level_texts.get(exposure_level, "niedrig")
    insights.append(f"Exposure-Level: {exposure_level}/5 ({level_text})")
    
    critical_count = len(evaluation.critical_points) if evaluation.critical_points else 0
    if critical_count > 0:
        insights.append(f"{critical_count} kritische Risikopunkte identifiziert")
        
        if critical_count <= 2:
            for point in evaluation.critical_points:
                insights.append(f"• {point}")
        else:
            first_points = evaluation.critical_points[:2]
            for point in first_points:
                insights.append(f"{point[:60]}" if len(point) > 60 else f" {point}")
            if critical_count > 2:
                insights.append(f" und {critical_count - 2} weitere Punkte")
    else:
        insights.append("Keine kritischen Risikopunkte identifiziert")
    
    # 4. Risikobewertung
    risk_level = evaluation.risk.value if hasattr(evaluation.risk, 'value') else str(evaluation.risk)
    insights.append(f"Risikobewertung: {risk_level.upper()}")
    
    # 5. Business Risk
    if business_risk.upper() in ["HIGH", "CRITICAL"]:
        insights.append("Erhöhter Handlungsbedarf")
    else:
        insights.append("Aktuell kontrollierte Risikosituation")
    
    return insights


def _generate_recommendations(
    business_risk: str,
    technical_json: Dict[str, Any],
    evaluation: Evaluation
) -> List[str]:
    """Generiere dynamische Empfehlungen."""
    
    base_recommendations = {
        "CRITICAL": [
            "Sofortige Notfallmaßnahmen einleiten",
            "Kritische Dienste temporär isolieren",
            "Incident-Response-Team informieren"
        ],
        "HIGH": [
            "Priorisierte Maßnahmen innerhalb von 7 Tagen",
            "Kritische Konfigurationen überprüfen", 
            "Monitoring intensivieren"
        ],
        "MEDIUM": [
            "Geplante Maßnahmen innerhalb von 30 Tagen",
            "Regelmäßige Sicherheitsscans etablieren",
            "Konfigurations-Härtung planen"
        ],
        "LOW": [
            "Keine sofortigen Notfallmaßnahmen erforderlich",
            "Kurzfristig: Einzelne Konfigurationen optimieren",
            "Mittelfristig: Kontinuierliches Monitoring aufbauen"
        ]
    }
    
    # Basis-Recommendations
    business_risk_upper = business_risk.upper()
    recommendations = base_recommendations.get(business_risk_upper, [
        "Regelmäßige Überprüfung der externen Angriffsfläche",
        "Security Awareness trainieren",
        "Proaktive Schwachstellenscans"
    ])
    
    # Spezifische Empfehlungen basierend auf technischen Daten
    open_ports = technical_json.get("open_ports", [])
    for port_info in open_ports:
        port = port_info.get("port")
        product = port_info.get("product", "").lower()
        
        if port == 22 and "ssh" in product:
            recommendations.append("SSH: Schlüsselbasierte Authentifizierung erzwingen")
        elif port in [80, 443] and any(x in product for x in ["http", "nginx", "apache"]):
            recommendations.append("Webserver: TLS 1.3 erzwingen, HSTS aktivieren")
        elif port == 3306 and "mysql" in product:
            recommendations.append("MySQL: Remote-Zugriff einschränken")
        elif port == 3389 and "rdp" in product:
            recommendations.append("RDP: Netzwerk-Level-Authentifizierung aktivieren")
    
    # Empfehlungen basierend auf kritischen Punkten
    if evaluation.critical_points:
        critical_count = len(evaluation.critical_points)
        if critical_count > 0:
            recommendations.append(f"Priorität: {critical_count} kritische Punkte adressieren")
            
        # Spezifische Empfehlungen für SSH/RDP
        for point in evaluation.critical_points:
            if "ssh" in point.lower():
                recommendations.append("SSH: Port ändern oder hinter VPN setzen")
            elif "rdp" in point.lower():
                recommendations.append("RDP: Nur über VPN zugänglich machen")
    
    return list(dict.fromkeys(recommendations))[:5]  # Duplikate entfernen, max 5