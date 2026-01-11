# src/shodan_report/pdf/pdf_manager.py
from reportlab.platypus import Spacer, Paragraph
from typing import List, Dict, Any, Optional
from .styles import _create_styles
from .sections.header import _create_header
from .sections.management import create_management_section
from .sections.technical import create_technical_section  
from .sections.trend import create_trend_section


def _create_footer(elements: List, styles: Dict) -> None:
    """Footer (später auch auslagern)."""
    from datetime import datetime
    from reportlab.platypus import Paragraph
    
    elements.append(Spacer(1, 24))
    
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


def prepare_pdf_elements(
    customer_name: str, 
    month: str, 
    ip: str, 
    management_text: str,
    trend_text: str, 
    technical_json: Dict[str, Any],
    evaluation: Dict[str, Any],
    business_risk: str,
    config: Optional[Dict] = None
) -> List:
   
    config = config or {}
    styling = config.get("styling", {})
    
    # Farben aus Config oder Default
    primary_hex = styling.get("primary_color", "#1a365d")
    secondary_hex = styling.get("secondary_color", "#2d3748")
    
    # Styles erstellen
    styles = _create_styles(primary_hex, secondary_hex)
    
    # PDF-Elemente aufbauen
    elements = []

    # 1. HEADER
    _create_header(elements, styles, customer_name, month, ip, config=config)

    # 2. MANAGEMENT-ZUSAMMENFASSUNG
    create_management_section(
        elements, 
        styles, 
        management_text,
        technical_json,
        evaluation,
        business_risk,
        config
    )
    
    # 3. TREND-ANALYSE
    create_trend_section(
        elements=elements,
        styles=styles,
        trend_text=trend_text,
        legacy_mode=False  # Einfach den Trend-Text durchreichen
        # compare_month könnten wir später hinzufügen
    )
    
    # 4. TECHNISCHER ANHANG
    create_technical_section(
        elements,
        styles,
        technical_json,
        config
    )
    
    # 5. FOOTER
    _create_footer(elements, styles)
    
    return elements