from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from datetime import datetime
from typing import List, Dict, Any, Optional

def _create_styles(primary_hex: str, secondary_hex: str) -> Dict[str, ParagraphStyle]:

    styles = getSampleStyleSheet()
    
    return {
        'title': ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=16,
            textColor=HexColor(primary_hex),
            spaceAfter=12,
            alignment=1
        ),
        'heading2': ParagraphStyle(
            'CustomHeading2',
            parent=styles['Heading2'],
            fontSize=12,
            textColor=HexColor(secondary_hex),
            spaceBefore=12,
            spaceAfter=6,
            leftIndent=0,
            borderPadding=(0, 0, 0, 6),
            borderColor=HexColor(primary_hex),
            borderWidth=(0, 0, 1, 0)
        ),
        'normal': ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceAfter=3
        ),
        'bullet': ParagraphStyle(
            'CustomBullet',
            parent=styles['Normal'],
            fontSize=10,
            leftIndent=20,
            firstLineIndent=-10,
            spaceAfter=2,
            bulletIndent=10
        ),
        'disclaimer': ParagraphStyle(
            'Disclaimer',
            parent=styles['Normal'],
            fontSize=7,
            textColor='gray',
            alignment=1,
            leading=10,
            spaceBefore=12,
            spaceAfter=6
        ),
        'footer': ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor='darkgray',
            alignment=1,
            leading=10
        )
    }


def _create_header(elements: List, styles: Dict, customer_name: str, month: str, ip: str, primary_hex: str) -> None:
    # Header    
    elements.append(Paragraph(f"<font color='{primary_hex}'>Sicherheitsreport</font>", styles['title']))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"<b>Kunde:</b> {customer_name}", styles['normal']))
    elements.append(Paragraph(f"<b>Monat:</b> {month}", styles['normal']))
    elements.append(Paragraph(f"<b>IP-Adresse:</b> {ip}", styles['normal']))
    
    # Trennlinie
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<hr width='100%' color='lightgray'/>", styles['normal']))
    elements.append(Spacer(1, 12))


def _create_management_section(elements: List, styles: Dict, management_text: str) -> None:
    # Füge Management-Zusammenfassung hinzu.
    elements.append(Paragraph("<b>Management-Zusammenfassung</b>", styles['heading2']))
    elements.append(Spacer(1, 6))
    
    for line in (management_text or "").splitlines():
        if line.strip():
            elements.append(Paragraph(line.strip(), styles['normal']))


def _create_trend_section(elements: List, styles: Dict, trend_text: str) -> None:
    # Trend-Analyse
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Historie / Trend</b>", styles['heading2']))
    elements.append(Spacer(1, 6))
    
    if trend_text:
        for line in trend_text.splitlines():
            if line.strip():
                elements.append(Paragraph(f"• {line.strip()}", styles['bullet']))
    else:
        elements.append(Paragraph("Keine historischen Daten für Trendanalyse vorhanden.", styles['normal']))


def _create_technical_section(elements: List, styles: Dict, technical_json: Dict) -> None:
    # Technischer Anhang
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Technischer Anhang</b>", styles['heading2']))
    elements.append(Spacer(1, 6))
    
    open_ports = technical_json.get("open_ports", [])
    
    for port_info in open_ports:
        port = port_info.get('port', '?')
        service = port_info.get('service', {})
        product = service.get('product', 'Unbekannt')
        
        version = service.get('version', '')
        version_str = f" ({version.strip()})" if version and len(version.strip()) < 20 else ""
        
        elements.append(Paragraph(f"• Port {port}: {product}{version_str}", styles['bullet']))


def _create_footer(elements: List, styles: Dict) -> None:
    # Disclaimer und Footer
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
    config: Optional[Dict] = None
) -> List:
    """
    Erstelle alle PDF-Elemente für den Sicherheitsreport.
    
    Args:
        customer_name: Name des Kunden
        month: Monat (YYYY-MM)
        ip: IP-Adresse
        management_text: Management-Zusammenfassung
        trend_text: Trend-Analyse
        technical_json: Technische Daten
        config: Kundenkonfiguration (optional)
    
    Returns:
        Liste von PDF-Elementen
    """
    config = config or {}
    styling = config.get("styling", {})
    
    # Farben aus Config oder Default
    primary_hex = styling.get("primary_color", "#1a365d")
    secondary_hex = styling.get("secondary_color", "#2d3748")
    
    # Styles erstellen
    styles = _create_styles(primary_hex, secondary_hex)
    
    # PDF-Elemente aufbauen
    elements = []
    
    _create_header(elements, styles, customer_name, month, ip, primary_hex)
    _create_management_section(elements, styles, management_text)
    _create_trend_section(elements, styles, trend_text)
    _create_technical_section(elements, styles, technical_json)
    _create_footer(elements, styles)
    
    return elements