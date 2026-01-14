"""
Priorisierte Handlungsempfehlungen für PDF-Reports.
"""

from typing import List, Dict, Any
from reportlab.platypus import Spacer, Paragraph, ListFlowable, ListItem


def create_recommendations_section(
    elements: List,
    styles: Dict,
    business_risk: str,
    technical_json: Dict[str, Any],
    evaluation: Dict[str, Any],
) -> None:
    """
    Erstelle Section mit priorisierten Handlungsempfehlungen.

    Args:
        elements: Liste der PDF-Elemente
        styles: Dictionary mit PDF-Styles
        business_risk: Business Risk Level (HIGH/MEDIUM/LOW)
        technical_json: Technische Daten
        evaluation: Evaluation Ergebnisse
    """
    elements.append(Spacer(1, 20))
    elements.append(
        Paragraph("<b>3. Priorisierte Handlungsempfehlungen</b>", styles["heading2"])
    )
    elements.append(Spacer(1, 12))

    # 1. Risikobasierte Basis-Empfehlungen
    risk_level = _extract_risk_level(business_risk)

    if risk_level.upper() == "HIGH":
        elements.append(
            Paragraph("<b>Priorität 1 – Sofort (0–7 Tage)</b>", styles["normal"])
        )
        priority_items = [
            "Kritische Dienste temporär isolieren oder härten",
            "Notfall-Response-Plan aktivieren",
            "24/7 Monitoring für betroffene Systeme",
        ]
    elif risk_level.upper() == "MEDIUM":
        elements.append(
            Paragraph(
                "<b>Priorität 1 – Mittelfristig (30–90 Tage)</b>", styles["normal"]
            )
        )
        priority_items = [
            "Aktualisierung der TLS-Konfiguration",
            "Abschaltung veralteter Protokolle (TLS 1.0 / 1.1)",
            "Überprüfung der Zertifikatslaufzeiten",
        ]
    else:  # LOW
        elements.append(
            Paragraph(
                "<b>Priorität 1 – Geplant (nächste 6 Monate)</b>", styles["normal"]
            )
        )
        priority_items = [
            "Regelmäßige Überprüfung neu auftretender Dienste",
            "Security Awareness Training planen",
            "Proaktive Schwachstellenscans etablieren",
        ]

    # Füge Priorität-1 Items als Liste hinzu
    for item in priority_items:
        elements.append(Paragraph(f"• {item}", styles["bullet"]))

    elements.append(Spacer(1, 8))

    # 2. Spezifische Empfehlungen basierend auf technischen Daten
    open_ports = technical_json.get("open_ports", [])
    if open_ports:
        elements.append(
            Paragraph(
                "<b>Priorität 2 – Spezifische Konfiguration</b>", styles["normal"]
            )
        )
        elements.append(Spacer(1, 4))

        for port_info in open_ports:
            port = _extract_port(port_info)

            # HTTPS ohne aktuelles Zertifikat
            if port == 443:
                elements.append(
                    Paragraph(
                        "• TLS-Zertifikate erneuern und Konfiguration aktualisieren",
                        styles["bullet"],
                    )
                )

            # SSH auf Standard-Port
            elif port == 22:
                elements.append(
                    Paragraph(
                        "• SSH-Zugriff auf Schlüssel-Authentifizierung umstellen",
                        styles["bullet"],
                    )
                )

            # DNS rekursiv
            elif port == 53:
                elements.append(
                    Paragraph(
                        "• Rekursive DNS-Anfragen auf interne Netze beschränken",
                        styles["bullet"],
                    )
                )


def _extract_risk_level(business_risk) -> str:
    """Extrahiert Risiko-Level aus verschiedenen Input-Formaten."""
    if isinstance(business_risk, dict):
        return str(business_risk.get("level", "MEDIUM"))
    elif isinstance(business_risk, str):
        return business_risk
    else:
        return str(business_risk)


def _extract_port(port_info):
    """Extrahiert Port-Nummer aus verschiedenen Formaten."""
    if isinstance(port_info, dict):
        return port_info.get("port")
    else:
        return port_info  # port_info ist schon der Port (int)
