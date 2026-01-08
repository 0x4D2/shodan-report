from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime

def prepare_pdf_elements(customer_name, month, ip, management_text, trend_text, technical_json):

    styles = getSampleStyleSheet()
    elements = []

    # Kopf
    elements.append(Paragraph(f"Kunde: {customer_name}<br/>Monat: {month}", styles['Normal']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Externer Sicherheitsreport</b>", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<b>IP-Adresse:</b> {ip}", styles['Heading3']))
    elements.append(Spacer(1, 12))

    # Management
    elements.append(Paragraph("<b>Management-Zusammenfassung</b>", styles['Heading2']))
    elements.append(Spacer(1, 6))
    for line in (management_text or "").splitlines():
        if line.strip():
            elements.append(Paragraph(line.strip(), styles['Normal']))
            elements.append(Spacer(1, 3))

    # Historie / Trend
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Historie / Trend</b>", styles['Heading2']))
    elements.append(Spacer(1, 6))
    if trend_text:
        for line in trend_text.splitlines():
            if line.strip():
                elements.append(Paragraph(f"• {line.strip()}", styles['Normal']))
    else:
        elements.append(Paragraph("Keine historischen Daten für Trendanalyse vorhanden.", styles['Italic']))

    # Technischer Anhang
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Technischer Anhang</b>", styles['Heading2']))
    elements.append(Spacer(1, 6))
    
    # HIER DER FIX:
    open_ports = technical_json.get("open_ports", [])
    
    for port_info in open_ports:
        port = port_info.get('port', '?')
        service = port_info.get('service', {})
        product = service.get('product', 'Unbekannt')
        
        # Nur Version anzeigen, wenn sie kurz ist (< 20 Zeichen)
        version = service.get('version', '')
        if version and len(version.strip()) < 20:
            version_str = f" ({version.strip()})"
        else:
            version_str = ""
        
        elements.append(Paragraph(f"• Port {port}: {product}{version_str}", styles['Normal']))

    # Footer
    elements.append(Spacer(1, 24))
    elements.append(Paragraph(f"<i>Erstellt am: {datetime.now().strftime('%d.%m.%Y %H:%M')}</i>", styles['Italic']))

    return elements