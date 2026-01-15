from typing import List, Dict, Any
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from shodan_report.pdf.layout import keep_section, set_table_repeat
from shodan_report.pdf.sections.data.technical_data import prepare_technical_detail


def create_technical_section(elements: List, styles: Dict, *args, **kwargs) -> None:
    # Support DI call: create_technical_section(elements, styles, context=ctx)
    technical_json = kwargs.get("technical_json", {})
    evaluation = kwargs.get("evaluation", None)
    if "context" in kwargs and kwargs.get("context") is not None:
        ctx = kwargs.get("context")
        technical_json = getattr(ctx, "technical_json", technical_json)
        evaluation = getattr(ctx, "evaluation", evaluation)

    elements.append(Spacer(1, 12))
    heading_style = styles.get("heading1", styles.get("heading2"))
    # keep legacy header text so existing tests that look for "Technischer Anhang" still match
    elements.append(keep_section([Paragraph("<b>4. Technischer Anhang — Technische Detailanalyse (Auszug)</b>", heading_style), Spacer(1, 12)]))

    if not technical_json:
        elements.append(Paragraph("Keine technischen Details verfügbar.", styles["normal"]))
        return

    data = prepare_technical_detail(technical_json or {}, evaluation)
    services = data.get("services", [])

    if not services:
        elements.append(Paragraph("Keine offenen Ports identifiziert.", styles["normal"]))
        return

    # Table: Port | Dienst | Version | Risiko
    header = [Paragraph("<b>Port</b>", styles["normal"]), Paragraph("<b>Dienst</b>", styles["normal"]), Paragraph("<b>Version</b>", styles["normal"]), Paragraph("<b>Risiko</b>", styles["normal"])]
    table_data = [header]
    for s in services:
        port_txt = str(s.get("port") or "-")
        prod = s.get("product") or "-"
        ver = s.get("version") or "-"
        risk = s.get("risk") or "-"
        table_data.append([Paragraph(port_txt, styles["normal"]), Paragraph(prod, styles["normal"]), Paragraph(ver, styles["normal"]), Paragraph(risk, styles["normal"])])

    tbl = Table(table_data, colWidths=[25 * mm, 80 * mm, 30 * mm, 30 * mm])
    set_table_repeat(tbl, 1)
    border_color = HexColor("#e5e7eb")
    header_bg = HexColor("#f8fafc")
    tbl.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.3, border_color),
                ("BACKGROUND", (0, 0), (-1, 0), header_bg),
                ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#111827")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(tbl)
    elements.append(Spacer(1, 8))

    # Add per-service details (TLS / CVE / Banner)
    top_vulns_count = 0
    try:
        if isinstance(technical_json, dict):
            top_vulns_count = len(technical_json.get("vulns") or technical_json.get("vulnerabilities") or [])
    except Exception:
        top_vulns_count = 0
    for s in services:
        details = []
        tls = s.get("tls", {}) or {}
        if tls.get("protocols"):
            details.append(f"TLS-Protokolle: {', '.join(tls.get('protocols'))}")
        if tls.get("weak_ciphers"):
            details.append("Schwache Cipher/Konfiguration identifiziert")
        if tls.get("cert_expiry"):
            details.append(f"Zertifikat gültig bis: {tls.get('cert_expiry')}")
        # Only show per-service CVE count when service has its own vulnerability list
        # Avoid repeating the host-level total for every service.
        svc_cve_count = s.get("cve_count") or 0
        if svc_cve_count and svc_cve_count != top_vulns_count:
            details.append(f"Bekannte Schwachstellen: {svc_cve_count} (hoch: {s.get('high_cvss')})")
        if s.get("banner"):
            b = s.get("banner")
            if isinstance(b, str) and len(b) > 0:
                short = b.replace('\n', ' ').strip()
                if len(short) > 140:
                    short = short[:137] + "..."
                details.append(f"Banner: {short}")

        if details:
            header_line = f"Port {s.get('port')}: {s.get('product') or '-'} ({s.get('version') or '-'})"
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(f"<b>{header_line}</b>", styles["normal"]))
            for d in details:
                elements.append(Paragraph(f"• {d}", styles["bullet"]))

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
