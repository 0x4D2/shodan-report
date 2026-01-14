"""
Methodik & Grenzen der Analyse für PDF-Reports.
"""

from typing import List, Dict
from reportlab.platypus import Spacer, Paragraph


def create_methodology_section(elements: List, styles: Dict) -> None:
    """
    Erstelle Section mit Methodik und Grenzen der Analyse.

    Args:
        elements: Liste der PDF-Elemente
        styles: Dictionary mit PDF-Styles
    """
    elements.append(Spacer(1, 20))
    elements.append(
        Paragraph("<b>6. Methodik & Grenzen der Analyse</b>", styles["heading2"])
    )
    elements.append(Spacer(1, 12))

    methodology_points = [
        "<b>Ausschließlich passive OSINT-Daten:</b>",
        "• Keine aktiven Scans oder Penetrationstests",
        "• Nur öffentlich verfügbare Informationen",
        "• Keine Authentifizierung oder Zugriff auf Systeme",
        "",
        "<b>Datengrundlage:</b>",
        "• Shodan.io Scan-Ergebnisse",
        "• Public Certificates & TLS-Konfigurationen",
        "• DNS-Auflösungen und Banner-Grabbing",
        "• Bekannte CVE-Datenbanken (NVD, Exploit-DB)",
        "",
        "<b>Limitationen & Ausschlüsse:</b>",
        "• Keine Garantie auf Vollständigkeit",
        "• Keine Aussage über interne Systeme",
        "• Keine Simulation realer Angriffe",
        "• Nicht öffentlich erreichbare Dienste werden nicht erfasst",
        "• Dynamische IP-Adressen können verfälschte Ergebnisse zeigen",
        "",
        "<b>Zeitlicher Rahmen:</b>",
        "• Momentaufnahme zum Analysezeitpunkt",
        "• Keine Echtzeit-Überwachung",
        "• Veränderungen nach Erstellung nicht erfasst",
    ]

    for point in methodology_points:
        if point.startswith("<b>"):
            # Überschrift
            elements.append(Paragraph(point, styles["normal"]))
        elif point.startswith("•"):
            # Bullet Point
            elements.append(Paragraph(point, styles["bullet"]))
        elif point == "":
            # Leerzeile
            elements.append(Spacer(1, 6))
        else:
            # Normaler Text
            elements.append(Paragraph(point, styles["normal"]))

    elements.append(Spacer(1, 8))
    elements.append(
        Paragraph(
            "<i>Diese Analyse ersetzt keinen Penetrationstest oder Sicherheitsaudit.</i>",
            styles["disclaimer"],
        )
    )
