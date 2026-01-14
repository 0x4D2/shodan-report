from reportlab.platypus import Paragraph, Spacer
from typing import List, Dict, Any


def create_technical_section(
    elements: List,
    styles: Dict,
    technical_json: Dict[str, Any],
    config: Dict[str, Any] = None,
) -> None:

    config = config or {}

    # 1. Überschrift
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Technischer Anhang</b>", styles["heading2"]))
    elements.append(Spacer(1, 6))

    open_ports = technical_json.get("open_ports", [])

    if not open_ports:
        elements.append(
            Paragraph("Keine offenen Ports identifiziert.", styles["normal"])
        )
        return

    # 2. Port-Informationen
    _add_port_information(elements, styles, open_ports)

    # 3. System-Metadaten
    _add_system_metadata(elements, styles, technical_json)

    # 4. Sicherheitshinweise
    _add_security_notes(elements, styles, technical_json)


def _add_port_information(elements: List, styles: Dict, open_ports: List[Dict]) -> None:
    elements.append(
        Paragraph("<b>Öffentlich erreichbare Dienste:</b>", styles["normal"])
    )
    elements.append(Spacer(1, 4))

    seen_ports = set()
    for port_info in open_ports:
        port = port_info.get("port", "?")
        transport = port_info.get("transport", "tcp").upper()

        port_key = f"{port}/{transport}"
        if port_key in seen_ports:
            continue
        seen_ports.add(port_key)

        service = port_info.get("service", {})
        product = service.get("product", "Unbekannter Dienst")
        version = service.get("version", "")
        banner = service.get("banner", "")
        extra_info = port_info.get("extra_info", "")

        port_text = _build_port_text(
            port, transport, product, version, banner, extra_info
        )
        elements.append(Paragraph(f"• {port_text}", styles["bullet"]))


def _build_port_text(
    port: int, transport: str, product: str, version: str, banner: str, extra_info: str
) -> str:
    port_text_parts = [f"<b>Port {port}/{transport}:</b> {product}"]

    # Version hinzufügen
    if version and version.strip():
        clean_version = version.strip().replace("\n", " ").replace("\r", "")
        if len(clean_version) < 40:
            port_text_parts.append(f"({clean_version})")

    # Extra-Informationen
    if extra_info:
        port_text_parts.append(f"<i>{extra_info}</i>")

    # Banner-Vorschau
    if banner and len(banner.strip()) > 0:
        clean_banner = banner.strip().replace("\n", " ").replace("\r", "")
        if len(clean_banner) < 80 and not any(
            x in clean_banner.lower() for x in ["<", ">", "{", "}"]
        ):
            port_text_parts.append(f"»{clean_banner}«")

    return " ".join(port_text_parts)


def _add_system_metadata(
    elements: List, styles: Dict, technical_json: Dict[str, Any]
) -> None:
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>System-Informationen:</b>", styles["normal"]))
    elements.append(Spacer(1, 4))

    meta_items = _extract_metadata_items(technical_json)

    if meta_items:
        for item in meta_items:
            elements.append(Paragraph(f"• {item}", styles["bullet"]))
    else:
        elements.append(
            Paragraph("Keine weiteren Metadaten verfügbar.", styles["normal"])
        )


def _extract_metadata_items(technical_json: Dict[str, Any]) -> List[str]:
    meta_items = []

    # Hostnames/Domains
    hostnames = technical_json.get("hostnames", [])
    if hostnames:
        meta_items.append(f"Hostname(s): {', '.join(hostnames[:3])}")

    # Organisation/ISP
    org = technical_json.get("org", "")
    isp = technical_json.get("isp", "")
    if org:
        meta_items.append(f"Organisation: {org}")
    elif isp:
        meta_items.append(f"ISP: {isp}")

    # Geolocation
    country = technical_json.get("country", "")
    city = technical_json.get("city", "")
    if country and city:
        meta_items.append(f"Standort: {city}, {country}")
    elif country:
        meta_items.append(f"Land: {country}")

    # ASN
    asn = technical_json.get("asn", "")
    if asn:
        meta_items.append(f"Autonomous System: {asn}")

    # Vulnerabilities
    vulnerabilities = technical_json.get("vulnerabilities", [])
    if vulnerabilities:
        meta_items.append(f"Identifizierte Schwachstellen: {len(vulnerabilities)}")

    # Kritische Services
    critical_services = technical_json.get("critical_services", [])
    if critical_services:
        high_critical = [c for c in critical_services if c.get("severity") == "high"]
        if high_critical:
            meta_items.append(f"Kritische Konfigurationen: {len(high_critical)}")

    return meta_items


def _add_security_notes(
    elements: List, styles: Dict, technical_json: Dict[str, Any]
) -> None:
    critical_services = technical_json.get("critical_services", [])

    if not critical_services:
        return

    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Sicherheitshinweise:</b>", styles["normal"]))
    elements.append(Spacer(1, 4))

    for critical in critical_services[:3]:  # Max 3 Hinweise
        port = critical.get("port", "")
        reason = critical.get("reason", "")
        severity = critical.get("severity", "medium")

        severity_icon = "⚠️" if severity == "high" else "ℹ️"
        elements.append(
            Paragraph(f"{severity_icon} Port {port}: {reason}", styles["bullet"])
        )
