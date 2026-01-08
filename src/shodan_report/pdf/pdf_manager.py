from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime

from reportlab.lib.colors import Color, black, navy, darkgray, HexColor
from reportlab.lib.units import inch, cm

def prepare_pdf_elements(customer_name, month, ip, management_text, trend_text, technical_json):
    styles = getSampleStyleSheet()
    
    # CUSTOM STYLES DEFINIEREN
    # Firmenfarbe: Blau (#1a365d)
    primary_color = HexColor('#1a365d')
    secondary_color = HexColor('#2d3748')
    
    # Titel-Style
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=16,
        textColor=primary_color,
        spaceAfter=12,
        alignment=1  # CENTER
    )
    
    # Heading 2
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=secondary_color,
        spaceBefore=12,
        spaceAfter=6,
        leftIndent=0,
        borderPadding=(0, 0, 0, 6),
        borderColor=primary_color,
        borderWidth=(0, 0, 1, 0)  # Unterstrich
    )
    
    # Normal mit besserem Zeilenabstand
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,  # Zeilenabstand
        spaceAfter=3
    )
    
    # Bullet Points
    bullet_style = ParagraphStyle(
        'CustomBullet',
        parent=styles['Normal'],
        fontSize=10,
        leftIndent=20,
        firstLineIndent=-10,
        spaceAfter=2,
        bulletIndent=10
    )
    
    elements = []
    
    # HEADER mit Logo Platzhalter
    elements.append(Paragraph(f"<font color='#1a365d'>Sicherheitsreport</font>", title_style))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"<b>Kunde:</b> {customer_name}", normal_style))
    elements.append(Paragraph(f"<b>Monat:</b> {month}", normal_style))
    elements.append(Paragraph(f"<b>IP-Adresse:</b> {ip}", normal_style))
    
    # Trennlinie
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<hr width='100%' color='lightgray'/>", normal_style))
    elements.append(Spacer(1, 12))
    
    # Management-Zusammenfassung
    elements.append(Paragraph("<b>Management-Zusammenfassung</b>", heading2_style))
    elements.append(Spacer(1, 6))
    
    for line in (management_text or "").splitlines():
        if line.strip():
            elements.append(Paragraph(line.strip(), normal_style))
    
    # Historie / Trend
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Historie / Trend</b>", heading2_style))
    elements.append(Spacer(1, 6))
    
    if trend_text:
        for line in trend_text.splitlines():
            if line.strip():
                elements.append(Paragraph(f"• {line.strip()}", bullet_style))
    else:
        elements.append(Paragraph("Keine historischen Daten für Trendanalyse vorhanden.", normal_style))
    
    # Technischer Anhang
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Technischer Anhang</b>", heading2_style))
    elements.append(Spacer(1, 6))
    
    open_ports = technical_json.get("open_ports", [])
    
    for port_info in open_ports:
        port = port_info.get('port', '?')
        service = port_info.get('service', {})
        product = service.get('product', 'Unbekannt')
        
        version = service.get('version', '')
        if version and len(version.strip()) < 20:
            version_str = f" ({version.strip()})"
        else:
            version_str = ""
        
        elements.append(Paragraph(f"• Port {port}: {product}{version_str}", bullet_style))
    
    # FOOTER mit Disclaimer
    elements.append(Spacer(1, 24))
    
    # Disclaimer
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontSize=7,
        textColor='gray',
        alignment=1,  # CENTER
        leading=10,
        spaceBefore=12,
        spaceAfter=6
    )
    
    disclaimer_text = f"""
    <font size='8'><b>HINWEIS ZUR VERWENDUNG:</b></font><br/>
    Dieser Bericht basiert auf öffentlich verfügbaren Informationen (OSINT) von Shodan.
    Er stellt keine vollständige Sicherheitsanalyse dar und ersetzt keinen Penetrationstest.
    Keine Garantie auf Vollständigkeit oder Richtigkeit. Dient ausschließlich zu Informationszwecken.
    <br/><br/>
    <i>Vertraulich. Stand: {datetime.now().strftime('%d.%m.%Y %H:%M')}</i>
    """
    
    elements.append(Paragraph(disclaimer_text, disclaimer_style))
    elements.append(Spacer(1, 6))
    
    # Trennlinie oben im Footer
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor='darkgray',
        alignment=1,  # CENTER
        leading=10
    )
    
    elements.append(Paragraph(f"Erstellt mit Shodan Report Generator • {datetime.now().strftime('%d.%m.%Y')}", footer_style))
    
    return elements