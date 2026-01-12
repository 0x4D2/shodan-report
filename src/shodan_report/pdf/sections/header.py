from reportlab.platypus import Paragraph, Spacer, Image
from datetime import datetime
from typing import List, Dict, Any, Optional
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm, inch
import os


def create_header_section(
    elements: List,
    styles: Dict,
    customer_name: str,
    month: str,
    ip: str,
    config: Dict[str, Any] = None,
    additional_assets: List[str] = None
) -> None:
    config = config or {}
    styling = config.get("styling", {})
    primary_hex = styling.get("primary_color", "#1a365d")
    secondary_hex = styling.get("secondary_color", "#2d3748")
    

    logo_path = styling.get("logo_path")
    if logo_path and os.path.exists(logo_path):
        try:
            logo_width = styling.get("logo_width", 2.0) * cm  # Default 2cm Breite
            logo_position = styling.get("logo_position", "center").lower()
            
            logo_img = Image(
                logo_path,
                width=logo_width,
                height=logo_width * 0.25,  # 4:1 Verhältnis 
                hAlign=logo_position.upper()  # 'LEFT', 'CENTER', 'RIGHT'
            )
            
            elements.append(logo_img)
            elements.append(Spacer(1, 4))  # Kleiner Abstand nach Logo
        except Exception as e:
            print(f"⚠️ Logo konnte nicht geladen werden: {logo_path} - {e}")
            
    
    title_text = f"""
    <font color='{primary_hex}' size='14'>
    <b>SICHERHEITSREPORT</b><br/>
    {customer_name}
    </font>
    """
    elements.append(Paragraph(title_text, ParagraphStyle(
        'CompactTitle',
        alignment=1,  # Center
        fontSize=14,
        textColor=primary_hex,
        spaceAfter=6,
    )))
    
    try:
        report_date = datetime.strptime(month, "%Y-%m")
        month_formatted = report_date.strftime("%b %Y")  # "Jan 2025"
    except ValueError:
        month_formatted = month
    
    # Assets abkürzen
    total_assets = 1 + (len(additional_assets) if additional_assets else 0)
    assets_text = f"{ip}" + (f" +{total_assets-1} assets" if total_assets > 1 else "")
    
    # Report-ID verbessern
    report_id = _generate_compact_report_id(customer_name, month, ip)
    
    metadata_line = f"""
    <font size='9'>
    <b>Scan:</b> {month_formatted} | 
    <b>Assets:</b> {assets_text} | 
    <b>Report-ID:</b> {report_id}
    </font>
    """
    
    elements.append(Paragraph(metadata_line, ParagraphStyle(
        'CompactMeta',
        alignment=1,
        fontSize=9,
        textColor="#000000",
        spaceAfter=4,
    )))
    
    elements.append(Paragraph(
        f"<hr width='80%' color='#d1d5db' size='0.25'/>", 
        ParagraphStyle('Hr', alignment=1)
    ))
    elements.append(Spacer(1, 8))  


def _generate_compact_report_id(customer_name: str, month: str, ip: str) -> str:
    import re
    from datetime import datetime
    
    # Kunden-Code: Erste 3-4 Buchstaben ohne Sonderzeichen
    clean_name = re.sub(r'[^A-Za-z]', '', customer_name)
    customer_code = clean_name[:3].upper() if clean_name else "CST"
    
    # Monats-Code: YYMM (z.B. "2601" für Jan 2026)
    month_code = month.replace('-', '')[-4:]
    
    # IP-Code: Letzte 3 Ziffern des letzten Oktetts
    ip_parts = ip.split('.')
    if len(ip_parts) == 4:
        last_octet = ip_parts[-1]
        ip_code = last_octet.zfill(3)  # Auf 3 Stellen auffüllen
    else:
        ip_code = "000"
    
    # Datum-Code: Tag des Monats (für Unterscheidung bei gleichem Kunden/Monat/IP)
    day_code = datetime.now().strftime("%d")
    
    return f"{customer_code}{month_code}{ip_code}{day_code}"
    # Beispiel: "CHI260106012" für CHINANET, Jan 2026, IP ...60, am 12ten


# Backward Compatibility
def _create_header(*args, **kwargs):
    """Legacy-Funktion für Backward Compatibility."""
    return create_header_section(*args, **kwargs)


def extract_assets_from_technical_data(technical_json: Dict[str, Any]) -> List[str]:
    assets = []
    
    if "domains" in technical_json and technical_json["domains"]:
        for domain in technical_json["domains"][:3]:
            assets.append(f"{domain} (Domain)")
    
    if "hostnames" in technical_json and technical_json["hostnames"]:
        for hostname in technical_json["hostnames"][:2]:
            assets.append(f"{hostname} (Hostname)")
    
    if "org" in technical_json and technical_json["org"]:
        assets.append(f"{technical_json['org']} (Organisation)")
    
    return assets