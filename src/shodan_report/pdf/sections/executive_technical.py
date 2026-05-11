from datetime import datetime
from typing import Any, Dict, List

from reportlab.lib.colors import HexColor
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from shodan_report.pdf.layout import keep_section


_PORT_NAMES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
}


def _iter_services(technical_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(technical_json.get("services") or technical_json.get("open_ports") or [])


def _service_name(service: Dict[str, Any]) -> str:
    port = service.get("port")
    product = str(service.get("product") or "").strip()
    if product:
        return product
    return _PORT_NAMES.get(port, str(port or "-"))


def _format_expiry(raw: str) -> str:
    if not raw:
        return "-"
    value = str(raw).strip()
    for fmt in ("%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).strftime("%d.%m.%Y")
        except ValueError:
            continue
    return value


def _tls_status(service: Dict[str, Any]) -> str:
    tls = service.get("tls") or {}
    days = tls.get("cert_expires_in_days")
    if isinstance(days, int):
        if days < 0:
            return "Abgelaufen"
        if days <= 30:
            return "Laeuft bald ab"
    if tls.get("cert_self_signed"):
        return "Selbstsigniert"
    if tls.get("cert_expiry") or tls.get("cert_valid_to"):
        return "OK"
    return "-"


def _system_rows(technical_json: Dict[str, Any], ip: str) -> List[List[Any]]:
    rows = []
    domains = list(technical_json.get("domains") or [])
    provider = technical_json.get("isp") or technical_json.get("org") or "-"
    asn = technical_json.get("asn") or "-"

    rows.append(["IP", ip or "-"])
    rows.append(["Domains", ", ".join(domains[:2]) if domains else "-"])
    rows.append(["Provider", str(provider)])
    rows.append(["ASN", str(asn)])
    return rows


def _build_system_table(styles: Dict[str, Any], technical_json: Dict[str, Any], ip: str) -> Table:
    data = [[
        Paragraph('<font size="8" color="#6B7280"><b>FELD</b></font>', styles["normal"]),
        Paragraph('<font size="8" color="#6B7280"><b>WERT</b></font>', styles["normal"]),
    ]]
    for label, value in _system_rows(technical_json, ip):
        data.append([
            Paragraph(f'<font size="8"><b>{label}</b></font>', styles["normal"]),
            Paragraph(f'<font size="8">{value}</font>', styles["normal"]),
        ])

    table = Table(data, colWidths=[36 * mm, 134 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F3F4F6")),
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#D1D5DB")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, HexColor("#E5E7EB")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return table


def _build_service_table(styles: Dict[str, Any], technical_json: Dict[str, Any]) -> Table:
    services = _iter_services(technical_json)
    data = [[
        Paragraph('<font size="8" color="#6B7280"><b>PORT</b></font>', styles["normal"]),
        Paragraph('<font size="8" color="#6B7280"><b>DIENST</b></font>', styles["normal"]),
        Paragraph('<font size="8" color="#6B7280"><b>ZERTIFIKAT</b></font>', styles["normal"]),
        Paragraph('<font size="8" color="#6B7280"><b>STATUS</b></font>', styles["normal"]),
    ]]

    for service in services[:6]:
        if not isinstance(service, dict):
            continue
        tls = service.get("tls") or {}
        expiry = _format_expiry(tls.get("cert_expiry") or tls.get("cert_valid_to") or "")
        data.append([
            Paragraph(f'<font size="8">{service.get("port") or "-"}</font>', styles["normal"]),
            Paragraph(f'<font size="8">{_service_name(service)}</font>', styles["normal"]),
            Paragraph(f'<font size="8">{expiry}</font>', styles["normal"]),
            Paragraph(f'<font size="8">{_tls_status(service)}</font>', styles["normal"]),
        ])

    table = Table(data, colWidths=[20 * mm, 55 * mm, 55 * mm, 40 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#F3F4F6")),
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#D1D5DB")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, HexColor("#E5E7EB")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return table


def create_executive_technical_section(elements: List, styles: Dict, *args, **kwargs) -> None:
    ctx = kwargs.get("context")
    if ctx is None:
        return

    technical_json = getattr(ctx, "technical_json", {}) or {}
    section = [
        Paragraph("2. Technische Details", styles["heading1"]),
        Spacer(1, 8),
        Paragraph("<b>System-Informationen</b>", styles["heading2"]),
        Spacer(1, 4),
        _build_system_table(styles, technical_json, getattr(ctx, "ip", "-")),
        Spacer(1, 10),
        Paragraph("<b>Erkannte Dienste</b>", styles["heading2"]),
        Spacer(1, 4),
        _build_service_table(styles, technical_json),
    ]
    elements.append(keep_section(section))