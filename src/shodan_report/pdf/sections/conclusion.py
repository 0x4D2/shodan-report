"""
Fazit-Section für PDF-Reports.
"""

from typing import List, Dict
from reportlab.platypus import Spacer, Paragraph


def create_conclusion_section(
    elements: List, styles: Dict, customer_name: str, business_risk: str
) -> None:
    """
    Erstelle Fazit-Section mit abschließender Bewertung.

    Args:
        elements: Liste der PDF-Elemente
        styles: Dictionary mit PDF-Styles
        customer_name: Name des Kunden
        business_risk: Business Risk Level (HIGH/MEDIUM/LOW)
    """
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("<b>7. Fazit</b>", styles["heading2"]))
    elements.append(Spacer(1, 12))

    # Risikobasierte Fazit-Formulierung
    risk_level = _extract_risk_level(business_risk)

    if risk_level.upper() in ["HIGH", "CRITICAL"]:
        conclusion_text = f"""
        Die externe Angriffsfläche der {customer_name} weist kritische Risiken auf, 
        die unmittelbare Maßnahmen erfordern. Es besteht akuter Handlungsbedarf, 
        um die identifizierten Schwachstellen zu adressieren und die Sicherheitslage 
        zu stabilisieren.
        """
        follow_up = "Eine sofortige Nachverfolgung und Priorisierung der kritischen Punkte wird dringend empfohlen."

    elif risk_level.upper() == "MEDIUM":
        conclusion_text = f"""
        Die externe Angriffsfläche der {customer_name} ist derzeit kontrollierbar, 
        zeigt jedoch strukturelle Schwachstellen, die bei fehlender Härtung 
        oder zukünftigen Sicherheitslücken zu einem erhöhten Risiko führen können.
        """
        follow_up = "Eine geplante Umsetzung der empfohlenen Maßnahmen innerhalb der nächsten 30-90 Tage wird empfohlen."

    else:  # LOW
        conclusion_text = f"""
        Die externe Angriffsfläche der {customer_name} ist überschaubar und 
        aktuell gut kontrolliert. Die identifizierten Punkte stellen kein 
        unmittelbares Sicherheitsrisiko dar.
        """
        follow_up = "Die kontinuierliche Beobachtung der externen Angriffsfläche wird als präventive Maßnahme empfohlen."

    # Füge Fazit-Text hinzu
    elements.append(Paragraph(conclusion_text, styles["normal"]))
    elements.append(Spacer(1, 8))

    # Allgemeine Empfehlung
    general_text = """
    Der größte Mehrwert ergibt sich aus der kontinuierlichen Beobachtung der 
    externen Angriffsfläche, um neue Exposures oder Schwachstellen frühzeitig 
    zu erkennen und proaktiv zu adressieren.
    """

    elements.append(Paragraph(general_text, styles["normal"]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(follow_up, styles["normal"]))

    # Optional: Call-to-Action
    elements.append(Spacer(1, 12))
    elements.append(
        Paragraph(
            "<i>Nächste Schritte: Besprechung der Ergebnisse und Planung konkreter Maßnahmen.</i>",
            styles["disclaimer"],
        )
    )


def _extract_risk_level(business_risk) -> str:
    """Extrahiert Risiko-Level (gleiche Funktion wie in recommendations)."""
    if isinstance(business_risk, dict):
        return str(business_risk.get("level", "MEDIUM"))
    elif isinstance(business_risk, str):
        return business_risk
    else:
        return str(business_risk)
