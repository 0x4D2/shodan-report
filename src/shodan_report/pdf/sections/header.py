from reportlab.platypus import Paragraph, Spacer
from datetime import datetime
from typing import List, Dict, Any
from shodan_report.pdf.styles import _create_styles


def _create_header(
    elements: List,
    styles: Dict,
    customer_name: str,
    month: str,
    ip: str,
    config: Dict[str, Any] = None,
    additional_assets: List[str] = None
) -> None:
    
    # Config mit Defaults mergen
    config = config or {}
    styling = config.get("styling", {})
    primary_hex = styling.get("primary_color", "#1a365d")
    secondary_hex = styling.get("secondary_color", "#2d3748")

    styles = _create_styles(primary_hex, secondary_hex)
    
    # 1. HAUPTTITEL
    title_text = f"""
    <font color='{primary_hex}'>Sicherheitsreport – Externe Angriffsflächenanalyse </font>
    """
    elements.append(Paragraph(title_text, styles['title']))
    elements.append(Spacer(1, 12))
    
    # 2. METADATEN (dynamisch!)
    try:
        report_date = datetime.strptime(month, "%Y-%m")
        month_formatted = report_date.strftime("%B %Y")  # "Januar 2025"
    except ValueError:
        month_formatted = month
    
    # Assets zusammenstellen
    assets_list = [f"• {ip} (primäre IP)"]
    if additional_assets:
        for asset in additional_assets:
            assets_list.append(f"• {asset}")
    
    # Zusätzliche Metadaten aus Config
    customer_data = config.get("customer", {})
    contact_email = customer_data.get("contact", "")
    customer_slug = customer_data.get("slug", customer_name.lower().replace(" ", "_"))
    
    # Metadaten-Text
    metadata_lines = [
        f"<b>Kunde:</b> {customer_name}",
        f"<b>Analysezeitraum:</b> {month_formatted}",
        f"<b>Analysierte Assets ({len(assets_list)}):</b>"
    ]
    
    # Assets hinzufügen
    for asset in assets_list:
        metadata_lines.append(f"&nbsp;&nbsp;&nbsp;&nbsp;{asset}")
    
    # Optionale Metadaten
    if contact_email:
        metadata_lines.append(f"<b>Kontakt:</b> {contact_email}")
    
    metadata_lines.append("<b>Datenquelle:</b> ua. Shodan (passiv, OSINT)")
    
    # Berichts-ID für Referenz, vllticht raus?
    report_id = f"{customer_slug}_{month.replace('-', '')}_{ip.replace('.', '-')}"
    metadata_lines.append(f"<b>Report-ID:</b> {report_id}")
    
    metadata_text = "<br/>".join(metadata_lines)
    elements.append(Paragraph(metadata_text, styles['normal']))
    elements.append(Spacer(1, 12))
    
    # 3. TRENNLINIE
    elements.append(Paragraph(f"<hr width='100%' color='{primary_hex}' size='0.5'/>", styles['normal']))
    elements.append(Spacer(1, 12))


def extract_assets_from_technical_data(technical_json: Dict[str, Any]) -> List[str]:
 
    assets = []
    
    # Domains extrahieren
    if "domains" in technical_json and technical_json["domains"]:
        for domain in technical_json["domains"][:3]:  # Max 3 Domains
            assets.append(f"{domain} (Domain)")
    
    # Hostnames extrahieren
    if "hostnames" in technical_json and technical_json["hostnames"]:
        for hostname in technical_json["hostnames"][:2]:  # Max 2 Hostnames
            assets.append(f"{hostname} (Hostname)")
    
    # Organisation (ISP)
    if "org" in technical_json and technical_json["org"]:
        assets.append(f"{technical_json['org']} (Organisation)")
    
    return assets