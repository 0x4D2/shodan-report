"""
Footer-Section für PDF-Reports.
Enthält Disclaimer, Copyright und Erstellungsdatum.
"""

from typing import List, Dict
from datetime import datetime
from reportlab.platypus import Spacer, Paragraph


def create_footer_section(elements: List, styles: Dict) -> None:
    """
    Erstelle Footer-Section mit Disclaimer und Metadaten.

    Args:
        elements: Liste der PDF-Elemente
        styles: Dictionary mit PDF-Styles
    """
    elements.append(Spacer(1, 16))

    _style = styles.get("disclaimer") or styles.get("normal")
    elements.append(Paragraph("<b>HINWEIS ZUR VERWENDUNG:</b>", _style))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        "Dieser Bericht basiert auf öffentlich verfügbaren Informationen (OSINT) von Shodan. "
        "Er stellt keine vollständige Sicherheitsanalyse dar und ersetzt keinen Penetrationstest. "
        "Keine Garantie auf Vollständigkeit oder Richtigkeit. Dient ausschließlich zu Informationszwecken.",
        _style,
    ))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        f"<i>Vertraulich. Stand: {datetime.now().strftime('%d.%m.%Y %H:%M')}</i>",
        _style,
    ))
