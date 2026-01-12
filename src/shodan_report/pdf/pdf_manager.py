# src/shodan_report/pdf/pdf_manager.py
from reportlab.platypus import Spacer, Paragraph
from typing import List, Dict, Any, Optional

from .styles import _create_styles
from .sections.header import _create_header
from .sections.management import create_management_section
from .sections.technical import create_technical_section  
from .sections.trend import create_trend_section
from .sections.footer import create_footer_section
from .sections.recommendations import create_recommendations_section
from .sections.methodology import create_methodology_section
from .sections.conclusion import create_conclusion_section
from .sections.cve_overview import create_cve_overview_section

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
   


    print(f"DEBUG: technical_json Keys: {list(technical_json.keys())}")
    print(f"DEBUG: Hat technical_json 'cves'? {'cves' in technical_json}")
    if 'cves' in technical_json:
        print(f"DEBUG: Anzahl CVEs: {len(technical_json['cves'])}")
        print(f"DEBUG: Erstes CVE Beispiel: {technical_json['cves'][0] if technical_json['cves'] else 'Keine'}")
        
    config = config or {}
    styling = config.get("styling", {})
    
    # Farben aus Config oder Default
    primary_hex = styling.get("primary_color", "#1a365d")
    secondary_hex = styling.get("secondary_color", "#2d3748")
    
    # Styles erstellen
    styles = _create_styles(primary_hex, secondary_hex)
    
    # PDF-Elemente aufbauen
    elements = []

    # 1. HEADER (Titel & Metadaten)
    _create_header(elements, styles, customer_name, month, ip, config=config)

    # 2. MANAGEMENT-ZUSAMMENFASSUNG (High-Level Übersicht)
    create_management_section(
        elements, 
        styles, 
        management_text,
        technical_json,
        evaluation,
        business_risk,
        config
    )
    
    # 3. TREND-ANALYSE (Entwicklung über Zeit)
    create_trend_section(
        elements=elements,
        styles=styles,
        trend_text=trend_text,
        legacy_mode=False
    )

    # 4. TECHNISCHER ANHANG (Details der gefundenen Dienste)
    create_technical_section(
        elements,
        styles,
        technical_json,
        config
    )

    # 5. CVE-ÜBERSICHT (Spezifische Schwachstellen)
    create_cve_overview_section(
        elements=elements,
        styles=styles,
        technical_json=technical_json,
        evaluation=evaluation
    )

    # 6. EMPFEHLUNGEN (Konkrete Maßnahmen)
    create_recommendations_section(
        elements=elements,
        styles=styles,
        business_risk=business_risk,
        technical_json=technical_json,
        evaluation=evaluation
    )

    # 7. METHODIK (Wie wurde analysiert)
    create_methodology_section(
        elements=elements,
        styles=styles
    )

    # 8. FAZIT (Abschließende Bewertung)
    create_conclusion_section(
        elements=elements,
        styles=styles,
        customer_name=customer_name,
        business_risk=business_risk
    )
    
    # 9. FOOTER (Disclaimer & Metadaten)
    create_footer_section(elements, styles)
    
    return elements