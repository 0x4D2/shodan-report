"""
Attack Surface Section — zeigt alle via Domain-Scout entdeckten IPs und Subdomains.
Wird nur gerendert wenn eine AttackSurface im ReportContext vorhanden ist.
"""

from typing import List, Dict, Any, Optional, TYPE_CHECKING

from reportlab.lib.colors import HexColor
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from shodan_report.pdf.layout import keep_section
from shodan_report.pdf.styles import Colors

if TYPE_CHECKING:
    from shodan_report.clients.domain_scout import AttackSurface


def create_attack_surface_section(
    elements: List,
    styles: Dict,
    attack_surface: Optional[Any] = None,
    context: Optional[Any] = None,
    **kwargs,
) -> None:
    """
    Rendert die Attack-Surface-Sektion in den PDF-Elements-Stream.

    Erwartet entweder `attack_surface` direkt oder liest es aus `context.attack_surface`.
    Rendert nichts wenn keine Daten vorhanden.
    """
    # Daten aus context oder direktem Parameter
    if attack_surface is None and context is not None:
        attack_surface = getattr(context, "attack_surface", None)

    if attack_surface is None:
        return

    relevant = attack_surface.relevant_ips
    cdn = attack_surface.cdn_ips
    subdomains = attack_surface.subdomains
    domain = attack_surface.domain

    col_w = [35 * mm, 30 * mm, 70 * mm, 40 * mm]
    full_w = sum(col_w)

    # ── Sektion sammeln für KeepTogether ─────────────────────────────────────
    sec: List = []

    # Überschrift
    sec.append(
        Paragraph(
            "<b>3. Attack Surface — Domain-Discovery</b>",
            styles.get("heading1", styles.get("Heading1")),
        )
    )
    sec.append(Spacer(1, 6))

    # Summary-Box
    summary_lines = [
        f"Domain: <b>{domain}</b>",
        f"{len(relevant)} direkt exponierte IP(s)  ·  "
        f"{len(cdn)} CDN/Proxy IP(s) gefiltert  ·  "
        f"{len(subdomains)} Subdomains aus Zertifikats-Historie",
    ]
    if attack_surface.primary_ip:
        summary_lines.append(
            f"Analysierte IP: <b>{attack_surface.primary_ip}</b>"
        )

    summary_data = [[Paragraph(line, styles.get("body", styles.get("Normal"))) for line in summary_lines[i:i+1]] for i in range(len(summary_lines))]

    summary_tbl = Table([[Paragraph(line, styles.get("body", styles.get("Normal")))] for line in summary_lines], colWidths=[full_w])
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f0f4ff")),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [HexColor("#f0f4ff")]),
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#1a365d")),
    ]))
    sec.append(summary_tbl)
    sec.append(Spacer(1, 10))

    # ── Relevante IPs ─────────────────────────────────────────────────────────
    if relevant:
        sec.append(
            Paragraph(
                "Direkt exponierte IPs — öffentlich erreichbar &amp; passiv ermittelt",
                styles.get("heading2", styles.get("Heading2")),
            )
        )
        sec.append(Spacer(1, 4))

        col_w_ips = [35 * mm, 25 * mm, 70 * mm, 45 * mm]
        header = [
            Paragraph("<b>IP-Adresse</b>",  styles.get("table_header", styles.get("Normal"))),
            Paragraph("<b>Typ</b>",          styles.get("table_header", styles.get("Normal"))),
            Paragraph("<b>Quellen</b>",      styles.get("table_header", styles.get("Normal"))),
            Paragraph("<b>Reverse DNS</b>",  styles.get("table_header", styles.get("Normal"))),
        ]

        rows = [header]
        for idx, sip in enumerate(relevant):
            ip_type = "Mailserver" if sip.is_mail else ("Nameserver" if sip.is_nameserver else "Server")
            rdns = sip.reverse_dns or "—"
            sources_text = "\n".join(f"• {s}" for s in sip.sources[:4])
            if len(sip.sources) > 4:
                sources_text += f"\n  … +{len(sip.sources)-4} weitere"

            row_style = styles.get("body_small", styles.get("Normal"))
            rows.append([
                Paragraph(sip.ip, row_style),
                Paragraph(ip_type, row_style),
                Paragraph(sources_text.replace("\n", "<br/>"), row_style),
                Paragraph(rdns, row_style),
            ])

        ip_tbl = Table(rows, colWidths=col_w_ips)
        bg_colors = [
            ("BACKGROUND", (0, 0), (-1, 0), Colors.primary),
            ("TEXTCOLOR",  (0, 0), (-1, 0), Colors.white),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
        for i in range(1, len(rows)):
            bg = HexColor("#f8fafc") if i % 2 == 0 else Colors.white
            bg_colors.append(("BACKGROUND", (0, i), (-1, i), bg))

        ip_tbl.setStyle(TableStyle([
            *bg_colors,
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("GRID",          (0, 0), (-1, -1), 0.3, HexColor("#e5e7eb")),
            ("LINEBELOW",     (0, 0), (-1, 0),  0.8, Colors.primary),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ]))
        sec.append(ip_tbl)
        sec.append(Spacer(1, 8))

    # ── CDN IPs ───────────────────────────────────────────────────────────────
    if cdn:
        sec.append(
            Paragraph(
                "CDN / Proxy IPs (gefiltert — kein direkter Serverkontakt)",
                styles.get("heading2", styles.get("Heading2")),
            )
        )
        sec.append(Spacer(1, 4))

        cdn_parts = [f"{sip.ip} ({sip.cdn})" for sip in cdn]
        cdn_text = " · ".join(cdn_parts)
        sec.append(
            Paragraph(
                f'<font color="#6b7280">{cdn_text}</font>',
                styles.get("body_small", styles.get("Normal")),
            )
        )
        sec.append(Spacer(1, 4))

        note_tbl = Table(
            [[Paragraph(
                "ℹ Diese IPs zeigen auf CDN-Infrastruktur (Cloudflare, Akamai o.ä.). "
                "Der eigentliche Webserver ist dahinter verborgen und ggf. nicht direkt analysierbar. "
                "Weitere Maßnahmen: Origin-IP-Leaks prüfen (DNS-History, E-Mail-Header, crt.sh).",
                styles.get("body_small", styles.get("Normal")),
            )]],
            colWidths=[full_w],
        )
        note_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#fefce8")),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#eab308")),
        ]))
        sec.append(note_tbl)
        sec.append(Spacer(1, 8))

    # ── Subdomains (kompakt) ──────────────────────────────────────────────────
    if subdomains:
        shown = subdomains[:20]
        remaining = len(subdomains) - len(shown)

        subdomain_text = " · ".join(shown)
        if remaining > 0:
            subdomain_text += f" · … +{remaining} weitere"

        sub_rows = [
            [Paragraph("<b>Subdomains aus Zertifikats-Historie (crt.sh)</b>",
                       styles.get("body", styles.get("Normal")))],
            [Paragraph(
                f'<font color="#374151" size="7">{subdomain_text}</font>',
                styles.get("body_small", styles.get("Normal")),
            )],
        ]
        sub_tbl = Table(sub_rows, colWidths=[full_w])
        sub_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), HexColor("#f8fafc")),
            ("BACKGROUND",    (0, 1), (-1, 1), Colors.white),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("BOX",           (0, 0), (-1, -1), 0.3, HexColor("#e5e7eb")),
            ("LINEBELOW",     (0, 0), (-1, 0),  0.3, HexColor("#e5e7eb")),
        ]))
        sec.append(sub_tbl)

    # Alles zusammen als Block einbetten
    elements.append(keep_section(sec))
    elements.append(Spacer(1, 12))
