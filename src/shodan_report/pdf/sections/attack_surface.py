"""
Attack Surface Section — zeigt alle via Domain-Scout entdeckten IPs und Subdomains.
Design: Summary-Bar mit 3 KPI-Zahlen, Typ-Badges, analysiertes Asset markiert (✦),
        Fußnoten-Box am Ende. Hochformat-optimiert.
"""

from typing import List, Dict, Any, Optional, TYPE_CHECKING

from reportlab.lib.colors import HexColor, white
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from shodan_report.pdf.layout import keep_section
from shodan_report.pdf.styles import Colors

if TYPE_CHECKING:
    from shodan_report.clients.domain_scout import AttackSurface


# ── Farben ────────────────────────────────────────────────────────────────────
C_BORDER        = HexColor("#DDDDDD")
C_HEADER_BG     = HexColor("#F8F8F8")
C_ROW_ALT       = HexColor("#FAFAFA")
C_SUMMARY_BG    = HexColor("#F8F8F8")
C_NOTE_BG       = HexColor("#F8F8F8")

C_SERVER_BG     = HexColor("#EEF4FF")
C_SERVER_BD     = HexColor("#B8D0F0")
C_SERVER_TX     = HexColor("#2563A8")

C_MAIL_BG       = HexColor("#FEF9ED")
C_MAIL_BD       = HexColor("#E8D090")
C_MAIL_TX       = HexColor("#A06010")

C_NS_BG         = HexColor("#F4F4F4")
C_NS_BD         = HexColor("#D0D0D0")
C_NS_TX         = HexColor("#666666")

# Spaltenbreiten Hochformat (nutzbare Breite ~175mm)
COL_IP   = 38 * mm
COL_TYPE = 26 * mm
COL_SRC  = 68 * mm
COL_RDNS = 43 * mm
FULL_W   = COL_IP + COL_TYPE + COL_SRC + COL_RDNS  # 175mm


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
    if attack_surface is None and context is not None:
        attack_surface = getattr(context, "attack_surface", None)

    if attack_surface is None:
        return

    relevant   = attack_surface.relevant_ips or []
    cdn        = attack_surface.cdn_ips or []
    subdomains = attack_surface.subdomains or []
    domain     = attack_surface.domain or "—"
    primary_ip = getattr(attack_surface, "primary_ip", None)

    sec: List = []

    # ── 1. Überschrift ────────────────────────────────────────────────────────
    sec.append(Paragraph(
        "<b>3. Attack Surface — Domain-Discovery</b>",
        styles.get("heading1", styles.get("Heading1")),
    ))
    sec.append(Spacer(1, 8))

    # ── 2. Summary-Bar ────────────────────────────────────────────────────────
    sec.append(_build_summary_bar(styles, domain, relevant, cdn, subdomains))
    sec.append(Spacer(1, 12))

    # ── 3. Tabellen-Subheader ─────────────────────────────────────────────────
    sec.append(Paragraph(
        "Direkt exponierte IPs — öffentlich erreichbar &amp; passiv ermittelt",
        styles.get("table_label", styles.get("Normal")),
    ))
    sec.append(Spacer(1, 5))

    # ── 4. IP-Tabelle ─────────────────────────────────────────────────────────
    if relevant:
        sec.append(_build_ip_table(styles, relevant, primary_ip))
        sec.append(Spacer(1, 10))

    # ── 5. CDN-Hinweis ────────────────────────────────────────────────────────
    if cdn:
        sec.append(_build_cdn_note(styles, cdn))
        sec.append(Spacer(1, 8))

    # ── 6. Subdomains ─────────────────────────────────────────────────────────
    if subdomains:
        sec.append(_build_subdomain_block(styles, subdomains))
        sec.append(Spacer(1, 8))

    # ── 7. Fußnoten-Box ───────────────────────────────────────────────────────
    sec.append(_build_footer_note(styles))

    elements.append(keep_section(sec))
    elements.append(Spacer(1, 12))


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY-BAR
# ─────────────────────────────────────────────────────────────────────────────

def _build_summary_bar(
    styles: Dict,
    domain: str,
    relevant: list,
    cdn: list,
    subdomains: list,
) -> Table:
    """
    Zweispaltige Bar:
    Links:  DOMAIN  <bold domain>
    Rechts: 3 KPI-Zahlen (exponierte IPs | CDN gefiltert | Subdomains)
    """
    s = styles.get("Normal")

    # Neue KPI-Bar: DOMAIN links, 3 dicke KPIs zentriert, alles in einer Zeile
    col_widths = [60 * mm, 38.33 * mm, 38.33 * mm, 38.33 * mm]  # Summe 175 mm
    bar = Table([
        [
            Paragraph('<font size="8" color="#888888"><b>DOMAIN</b></font><br/><font size="14" color="#1a1a1a"><b>' + domain + '</b></font>', s),
            Paragraph('<para align="center"><font size="18" color="#1a1a1a"><b>' + str(len(relevant)) + '</b></font><br/><font size="8" color="#888888">EXPONIERTE IPS</font></para>', s),
            Paragraph('<para align="center"><font size="18" color="#1a1a1a"><b>' + str(len(cdn)) + '</b></font><br/><font size="8" color="#888888">CDN GEFILTERT</font></para>', s),
            Paragraph('<para align="center"><font size="18" color="#1a1a1a"><b>' + str(len(subdomains)) + '</b></font><br/><font size="8" color="#888888">SUBDOMAINS (CRT.SH)</font></para>', s),
        ]
    ], colWidths=col_widths)
    bar.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_SUMMARY_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LINEBEFORE",    (1, 0), (1, 0), 0.5, C_BORDER),
        ("LINEBEFORE",    (2, 0), (2, 0), 0.5, C_BORDER),
        ("LINEBEFORE",    (3, 0), (3, 0), 0.5, C_BORDER),
    ]))
    return bar


# ─────────────────────────────────────────────────────────────────────────────
# IP-TABELLE
# ─────────────────────────────────────────────────────────────────────────────

def _build_ip_table(
    styles: Dict,
    relevant: list,
    primary_ip: Optional[str],
) -> Table:
    """
    Spalten: IP-ADRESSE | TYP | QUELLEN | REVERSE DNS
    - Analysierte IP: ✦ Markierung + leicht blauer Hintergrund
    - Typ-Spalte: farbiger Hintergrund je nach Server/Mail/NS
    - Alternierende Zeilenfarben
    """
    s_hdr  = styles.get("Normal")
    s_body = styles.get("body_small", styles.get("Normal"))

    header = [
        Paragraph('<font size="8" color="#666666"><b>IP-ADRESSE</b></font>',  s_hdr),
        Paragraph('<font size="8" color="#666666"><b>TYP</b></font>',          s_hdr),
        Paragraph('<font size="8" color="#666666"><b>QUELLEN</b></font>',      s_hdr),
        Paragraph('<font size="8" color="#666666"><b>REVERSE DNS</b></font>',  s_hdr),
    ]
    rows         = [header]
    type_colors  = []   # (row_idx, bg)
    primary_rows = []

    for idx, sip in enumerate(relevant):
        row_idx = idx + 1


        # Badge-Design für Typ
        if sip.is_mail:
            ip_type = "Mailserver"
            badge_bg = C_MAIL_BG
            badge_bd = C_MAIL_BD
            badge_tx = C_MAIL_TX
        elif sip.is_nameserver:
            ip_type = "Nameserver"
            badge_bg = C_NS_BG
            badge_bd = C_NS_BD
            badge_tx = C_NS_TX
        else:
            ip_type = "Server"
            badge_bg = C_SERVER_BG
            badge_bd = C_SERVER_BD
            badge_tx = C_SERVER_TX


        is_primary = bool(primary_ip and sip.ip == primary_ip)
        if is_primary:
            primary_rows.append(row_idx)

        ip_display = f"{sip.ip} ✦" if is_primary else sip.ip

        src_lines = sip.sources[:4]
        src_text  = "<br/>".join(f"• {s}" for s in src_lines)
        if len(sip.sources) > 4:
            src_text += f"<br/>… +{len(sip.sources)-4} weitere"

        rdns = sip.reverse_dns or "—"

        # Badge als kleine 1x1-Tabelle, Breite dynamisch, Padding minimal
        badge = Table(
            [[Paragraph(f'<font size="9" color="#{_hex(badge_tx)}"><b>{ip_type}</b></font>', s_body)]],
        )
        badge.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, 0), badge_bg),
            ("BOX",           (0, 0), (0, 0), 0.8, badge_bd),
            ("ALIGN",         (0, 0), (0, 0), "CENTER"),
            ("VALIGN",        (0, 0), (0, 0), "MIDDLE"),
            ("LEFTPADDING",   (0, 0), (0, 0), 1.5),
            ("RIGHTPADDING",  (0, 0), (0, 0), 1.5),
            ("TOPPADDING",    (0, 0), (0, 0), 0.5),
            ("BOTTOMPADDING", (0, 0), (0, 0), 0.5),
        ]))

        rows.append([
            Paragraph(f'<font size="9" color="#1a1a1a">{ip_display}</font>', s_body),
            badge,
            Paragraph(f'<font size="9" color="#555555">{src_text}</font>',   s_body),
            Paragraph(f'<font size="9" color="#888888">{rdns}</font>',       s_body),
        ])

    tbl = Table(rows, colWidths=[COL_IP, COL_TYPE, COL_SRC, COL_RDNS])

    ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_HEADER_BG),
        ("LINEBELOW",     (0, 0), (-1, 0),  0.8, C_BORDER),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ])

    # Alternierende Zeilenhintergründe
    for i in range(1, len(rows)):
        bg = C_ROW_ALT if i % 2 == 0 else white
        ts.add("BACKGROUND", (0, i), (-1, i), bg)

    # Typ-Spalte: keine Zellenfärbung mehr, da Badge verwendet wird

    # Primary-IP IP-Zelle hervorheben
    for row_idx in primary_rows:
        ts.add("BACKGROUND", (0, row_idx), (0, row_idx), HexColor("#EEF4FF"))

    tbl.setStyle(ts)
    return tbl


# ─────────────────────────────────────────────────────────────────────────────
# CDN-HINWEIS
# ─────────────────────────────────────────────────────────────────────────────

def _build_cdn_note(styles: Dict, cdn: list) -> Table:
    s        = styles.get("body_small", styles.get("Normal"))
    cdn_text = " · ".join(
        f"{sip.ip} ({getattr(sip, 'cdn', 'CDN')})" for sip in cdn
    )
    note = Table(
        [[Paragraph(
            f'<font size="9" color="#666666">'
            f'CDN/Proxy IPs gefiltert: {cdn_text}<br/>'
            f'Der eigentliche Webserver ist dahinter verborgen. '
            f'Origin-IP-Leaks prüfen (DNS-History, E-Mail-Header, crt.sh).'
            f'</font>',
            s,
        )]],
        colWidths=[FULL_W],
    )
    note.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#FEFCE8")),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#EAB308")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return note


# ─────────────────────────────────────────────────────────────────────────────
# SUBDOMAIN-BLOCK
# ─────────────────────────────────────────────────────────────────────────────

def _build_subdomain_block(styles: Dict, subdomains: list) -> Table:
    s         = styles.get("body_small", styles.get("Normal"))
    shown     = subdomains[:20]
    remaining = len(subdomains) - len(shown)
    sub_text  = " · ".join(shown)
    if remaining > 0:
        sub_text += f" · … +{remaining} weitere"

    tbl = Table(
        [
            [Paragraph(
                '<font size="8" color="#333333"><b>'
                'Subdomains aus Zertifikats-Historie (crt.sh)'
                '</b></font>',
                s,
            )],
            [Paragraph(f'<font size="8" color="#555555">{sub_text}</font>', s)],
        ],
        colWidths=[FULL_W],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_HEADER_BG),
        ("BACKGROUND",    (0, 1), (-1, 1), white),
        ("BOX",           (0, 0), (-1, -1), 0.3, C_BORDER),
        ("LINEBELOW",     (0, 0), (-1, 0),  0.3, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return tbl


# ─────────────────────────────────────────────────────────────────────────────
# FUSSNOTENBOX
# ─────────────────────────────────────────────────────────────────────────────

def _build_footer_note(styles: Dict) -> Table:
    s    = styles.get("body_small", styles.get("Normal"))
    note = Table(
        [[Paragraph(
            '<font size="8.5" color="#444444">'
            '✦ Analysiertes Asset — nur diese IP wird via Shodan bewertet. '
            'Alle weiteren IPs und Hostnamen werden als Netzwerk-Identitäten aufgeführt, '
            'aber nicht separat analysiert. Subdomains wie shop., awareness., firewall. '
            'sind öffentlich sichtbar und für Angreifer direkt einsehbar.'
            '</font>',
            s,
        )]],
        colWidths=[FULL_W],
    )
    note.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_NOTE_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return note


# ─────────────────────────────────────────────────────────────────────────────
# HILFSFUNKTIONEN
# ─────────────────────────────────────────────────────────────────────────────

def _hex(c) -> str:
    """HexColor → 6-stelliger Hex-String ohne #."""
    return f"{int(c.red*255):02X}{int(c.green*255):02X}{int(c.blue*255):02X}"