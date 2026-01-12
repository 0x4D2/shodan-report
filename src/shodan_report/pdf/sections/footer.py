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
    elements.append(Spacer(1, 24))
    
    # Disclaimer Text
    disclaimer_text = f"""
    <font size='8'><b>HINWEIS ZUR VERWENDUNG:</b></font><br/>
    Dieser Bericht basiert auf öffentlich verfügbaren Informationen (OSINT) von Shodan.
    Er stellt keine vollständige Sicherheitsanalyse dar und ersetzt keinen Penetrationstest.
    Keine Garantie auf Vollständigkeit oder Richtigkeit. Dient ausschließlich zu Informationszwecken.
    <br/><br/>
    <i>Vertraulich. Stand: {datetime.now().strftime('%d.%m.%Y %H:%M')}</i>
    """
    
    elements.append(Paragraph(disclaimer_text, styles['disclaimer']))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        f"Erstellt mit Shodan Report Generator • {datetime.now().strftime('%d.%m.%Y')}", 
        styles['footer']
    ))