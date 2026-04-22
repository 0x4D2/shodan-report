"""
Letzte Seite: Hinweis zur Verwendung + Grenzen + Vertraulichkeit + Signatur-Block.
Design: große Disclaimer-Box oben, zweispaltig Grenzen/Vertraulichkeit, Signatur unten.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from reportlab.platypus import Spacer, Paragraph, Table, TableStyle, HRFlowable
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white


# ── Farben ────────────────────────────────────────────────────────────────────
C_BORDER      = HexColor("#DDDDDD")
C_BOX_BG      = HexColor("#F8F8F8")
C_LIMITS_BG   = HexColor("#F8F8F8")
C_BULLET      = HexColor("#AAAAAA")


def create_footer_section(
    elements: List,
    styles: Dict,
    context: Optional[Any] = None,
    sha256: Optional[str] = None,
    **kwargs,
) -> None:
    """
    Letzte Seite: Disclaimer, Grenzen, Vertraulichkeit, Signatur.
    """
    ns = styles.get("normal") or styles.get("Normal")

    from reportlab.platypus import PageBreak
    elements.append(PageBreak())
    elements.append(Spacer(1, 12))

    # ── Haupt-Disclaimer-Box ──────────────────────────────────────────────────
    disclaimer_text = (
        "Dieser Bericht basiert ausschließlich auf passiver OSINT-Analyse öffentlich zugänglicher Quellen "
        "(Shodan, NVD, CISA KEV, DNS- und TLS-Daten). Er ersetzt keinen Penetrationstest und stellt keine "
        "interne Sicherheitsüberprüfung dar. Grenzen und Vertraulichkeitsbedingungen siehe unten."
    )

    disc_inner = Table([
        [Paragraph(
            '<font size="9" color="#1A1A1A"><b>HINWEIS ZUR VERWENDUNG</b></font>',
            ns,
        )],
        [Paragraph(
            f'<font size="9" color="#444444">{disclaimer_text}</font>',
            ns,
        )],
    ], colWidths=[175 * mm])
    disc_inner.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_BOX_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("LINEBELOW",     (0, 0), (0, 0),   0.5, C_BORDER),
    ]))
    elements.append(disc_inner)
    elements.append(Spacer(1, 16))

    # ── Zweispaltig: Grenzen | Vertraulichkeit ────────────────────────────────
    left  = _build_limits_box(styles)
    right = _build_confidentiality_box(styles)

    two_col = Table([[left, right]], colWidths=[86 * mm, 89 * mm])
    two_col.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (0, 0),   6),
    ]))
    elements.append(two_col)
    elements.append(Spacer(1, 24))

    # ── Signatur-Block ────────────────────────────────────────────────────────
    _build_signature_block(elements, styles, context, sha256)


# ─────────────────────────────────────────────────────────────────────────────
# GRENZEN-BOX
# ─────────────────────────────────────────────────────────────────────────────

def _build_limits_box(styles: Dict) -> Table:
    ns = styles.get("normal") or styles.get("Normal")

    limits = [
        "Momentaufnahme — Lage kann sich täglich ändern",
        "Keine interne Netzwerksicht, keine Authentifizierung",
        "CVE-Zuordnungen nicht aktiv verifiziert (Inferred)",
        "Interne Kontrollen (Firewall, MFA) fließen nicht ein",
        "Keine Garantie auf Vollständigkeit der Discovery",
    ]

    rows = [[Paragraph(
        '<font size="8" color="#666666"><b>GRENZEN DIESER ANALYSE</b></font>', ns
    )]]
    for item in limits:
        rows.append([Paragraph(
            f'<font size="8" color="#555555">• {item}</font>', ns
        )])

    tbl = Table(rows, colWidths=[84 * mm])
    tbl.setStyle(TableStyle([
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("BACKGROUND",    (0, 0), (-1, 0), HexColor("#F0F0F0")),
        ("BACKGROUND",    (0, 1), (-1, -1), white),
        ("LINEBELOW",     (0, 0), (-1, 0),  0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    return tbl


# ─────────────────────────────────────────────────────────────────────────────
# VERTRAULICHKEITS-BOX
# ─────────────────────────────────────────────────────────────────────────────

def _build_confidentiality_box(styles: Dict) -> Table:
    ns = styles.get("normal") or styles.get("Normal")

    items = [
        "Report vertraulich — nur für benannte Empfänger",
        "Datenlöschung nach 30 Tagen (IP, Domain, Report)",
        "Keine Weitergabe an Dritte",
        "SHA256-gesichert, manipulationssicher archiviert",
        "Versioniert — Archiv-Nachweis auf Anfrage (Corporate)",
    ]

    rows = [[Paragraph(
        '<font size="8" color="#666666"><b>VERTRAULICHKEIT &amp; ARCHIVIERUNG</b></font>', ns
    )]]
    for item in items:
        rows.append([Paragraph(
            f'<font size="8" color="#555555">• {item}</font>', ns
        )])

    tbl = Table(rows, colWidths=[87 * mm])
    tbl.setStyle(TableStyle([
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("BACKGROUND",    (0, 0), (-1, 0), HexColor("#F0F0F0")),
        ("BACKGROUND",    (0, 1), (-1, -1), white),
        ("LINEBELOW",     (0, 0), (-1, 0),  0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    return tbl


# ─────────────────────────────────────────────────────────────────────────────
# SIGNATUR-BLOCK
# ─────────────────────────────────────────────────────────────────────────────

def _build_signature_block(
    elements: List,
    styles: Dict,
    context: Optional[Any],
    sha256: Optional[str],
) -> None:
    ns = styles.get("normal") or styles.get("Normal")

    now_str = datetime.now().strftime("%d. %B %Y · %H:%M Uhr").replace(
        "January", "Januar").replace("February", "Februar").replace(
        "March", "März").replace("April", "April").replace(
        "May", "Mai").replace("June", "Juni").replace(
        "July", "Juli").replace("August", "August").replace(
        "September", "September").replace("October", "Oktober").replace(
        "November", "November").replace("December", "Dezember")

    left_lines = [
        '<font size="10" color="#1A1A1A"><b>ichwillsicherheit.de — MG Solutions</b></font>',
        '<font size="9" color="#666666">Lage, Deutschland</font>',
        '<font size="9" color="#666666">Mitglied im Cyber-Sicherheitsnetzwerk Deutschland (BSI)</font>',
        f'<font size="8" color="#AAAAAA">Stand: {now_str}</font>',
    ]

    right_lines = [
        '<font size="8" color="#666666">Prüfsumme (SHA256) jeder Seite</font>',
        '<font size="8" color="#AAAAAA">in der Fußzeile des Reports ausgewiesen.</font>',
    ]

    left_cell = Table(
        [[Paragraph(line, ns)] for line in left_lines],
        colWidths=[100 * mm],
    )
    left_cell.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))

    right_cell = Table(
        [[Paragraph(line, ns)] for line in right_lines],
        colWidths=[75 * mm],
    )
    right_cell.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("ALIGN",         (0, 0), (-1, -1), "RIGHT"),
    ]))

    sig_tbl = Table([[left_cell, right_cell]], colWidths=[100 * mm, 75 * mm])
    sig_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "BOTTOM"),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("LINEABOVE",     (0, 0), (-1, 0),  0.5, C_BORDER),
    ]))
    elements.append(sig_tbl)