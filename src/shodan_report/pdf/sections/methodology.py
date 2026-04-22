"""
Einordnung & Bewertungslogik — Seite 8.
Design: Datenbasis-Box oben, zweispaltig (Begriffe links | Exposure-Level-Tabelle rechts),
darunter Attack-Surface-Discovery Bullets.
"""

from typing import List, Dict, Any
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white
from reportlab.graphics.shapes import Drawing, Circle


# ── Farben ────────────────────────────────────────────────────────────────────
C_BORDER   = HexColor("#DDDDDD")
C_NOTE_BG  = HexColor("#F8F8F8")
C_GREEN    = HexColor("#27AE60")
C_ORANGE   = HexColor("#E67E22")
C_RED      = HexColor("#C0392B")

# Exposure-Level Farben: 1=grün, 2=grün, 3=orange, 4=rot, 5=rot
_LEVEL_COLORS = {
    1: HexColor("#27AE60"),
    2: HexColor("#27AE60"),
    3: HexColor("#E67E22"),
    4: HexColor("#C0392B"),
    5: HexColor("#C0392B"),
}
_LEVEL_LABELS = {
    1: "minimal",
    2: "niedrig–mittel",
    3: "erhöht",
    4: "hoch",
    5: "kritisch",
}
_LEVEL_FACTORS = {
    1: "Keine öffentlichen Dienste",
    2: "Webdienste, kein SSH/DB",
    3: "Admin-Dienste, CVE-Indikatoren",
    4: "RDP, kritische CVEs, EOL",
    5: "Aktive Exploits, CISA KEV",
}


def create_methodology_section(
    elements: List[Any], styles: Dict[str, Any], *args, **kwargs
) -> None:
    """
    Einordnung & Bewertungslogik.
    Zweispaltiges Layout: Begriffe | Exposure-Level-Tabelle + Discovery-Liste.
    """
    ns = styles.get("normal") or styles.get("Normal")

    elements.append(Spacer(1, 12))
    heading_style = styles.get("heading1") or styles.get("heading2") or ns
    elements.append(Paragraph(
        "<b>9. Einordnung &amp; Bewertungslogik</b>", heading_style
    ))
    elements.append(Spacer(1, 10))

    # ── Datenbasis-Box ────────────────────────────────────────────────────────
    note_tbl = Table([[Paragraph(
        '<font size="8" color="#888888">'
        "Datenbasis: ausschließlich OSINT (öffentlich zugängliche Informationen) — "
        "keine aktiven Scans, keine internen Systeme, keine Authentifizierung."
        "</font>",
        ns,
    )]], colWidths=[175 * mm])
    note_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_NOTE_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(note_tbl)
    elements.append(Spacer(1, 14))

    # ── Zweispaltig: Begriffe | Exposure-Level ────────────────────────────────
    left  = _build_terms_column(styles)
    right = _build_exposure_column(styles)

    two_col = Table([[left, right]], colWidths=[85 * mm, 90 * mm])
    two_col.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (0, 0), 12),
    ]))
    elements.append(two_col)
    elements.append(Spacer(1, 14))

    # ── Attack Surface Discovery ──────────────────────────────────────────────
    _build_discovery_block(elements, styles)


# ─────────────────────────────────────────────────────────────────────────────
# LINKE SPALTE: BEGRIFFE
# ─────────────────────────────────────────────────────────────────────────────

def _build_terms_column(styles: Dict) -> Table:
    ns = styles.get("normal") or styles.get("Normal")

    terms = [
        (
            "Verified Finding",
            "Direkt beobachtetes Faktum — z.\u202fB. aktives TLS-Protokoll, offener Port. "
            "Messwert, kein Schluss.",
        ),
        (
            "Inferred Finding",
            "Abgeleitete Erkenntnis via Versionserkennung — z.\u202fB. mögliche CVEs. "
            "Nicht aktiv verifiziert.",
        ),
        (
            "CVE / CVSS",
            "Dokumentierte Schwachstelle mit Schwerebewertung 0–10.",
        ),
        (
            "EOL (End of Life)",
            "Software ohne Sicherheits-Support — strukturell nicht mehr patchbar.",
        ),
        (
            "CISA KEV",
            "Known Exploited Vulnerabilities — aktiv in der Praxis ausgenutzte CVEs.",
        ),
    ]

    rows = []
    for title, body in terms:
        rows.append([Paragraph(
            f'<font size="9" color="#1A1A1A"><b>{title}</b></font><br/>'
            f'<font size="8" color="#666666">{body}</font>',
            ns,
        )])

    # Header
    header_row = [Paragraph(
        '<font size="9" color="#1A1A1A"><b>Begriffe</b></font>', ns
    )]

    tbl = Table([header_row] + rows, colWidths=[83 * mm])
    tbl.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.3, HexColor("#EEEEEE")),
        ("TOPPADDING",    (0, 0), (0, 0),   0),
        ("BOTTOMPADDING", (0, 0), (0, 0),   8),
    ]))
    return tbl


# ─────────────────────────────────────────────────────────────────────────────
# RECHTE SPALTE: EXPOSURE-LEVEL TABELLE
# ─────────────────────────────────────────────────────────────────────────────

def _build_exposure_column(styles: Dict) -> Table:
    ns = styles.get("normal") or styles.get("Normal")

    def _dot(color: HexColor) -> Drawing:
        d = Drawing(10, 10)
        d.add(Circle(5, 5, 4, fillColor=color, strokeColor=color, strokeWidth=0))
        return d

    # Header
    header = [
        Paragraph('<font size="9" color="#1A1A1A"><b>Exposure-Level (1–5)</b></font>', ns),
        Spacer(1, 1),
        Spacer(1, 1),
    ]

    rows = [[
        Paragraph('<font size="8" color="#666666"><b>LEVEL</b></font>', ns),
        Paragraph('<font size="8" color="#666666"><b>EINSCHÄTZUNG</b></font>', ns),
        Paragraph('<font size="8" color="#666666"><b>TYPISCHE FAKTOREN</b></font>', ns),
    ]]

    for level in range(1, 6):
        color = _LEVEL_COLORS[level]
        label = _LEVEL_LABELS[level]
        factor = _LEVEL_FACTORS[level]
        hex_color = "#{:02X}{:02X}{:02X}".format(
            int(color.red * 255), int(color.green * 255), int(color.blue * 255)
        )
        rows.append([
            # Level-Nummer mit farbigem Punkt
            Table([[
                _dot(color),
                Paragraph(f'<font size="9" color="#1A1A1A">{level}</font>', ns),
            ]], colWidths=[6 * mm, 8 * mm]),
            Paragraph(f'<font size="9" color="{hex_color}">{label}</font>', ns),
            Paragraph(f'<font size="8" color="#666666">{factor}</font>', ns),
        ])

    level_tbl = Table(rows, colWidths=[14 * mm, 28 * mm, 45 * mm])
    level_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), HexColor("#F8F8F8")),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#DDDDDD")),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, HexColor("#EEEEEE")),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))

    # Wrapper mit Header-Text
    wrapper = Table([
        [Paragraph('<font size="9" color="#1A1A1A"><b>Exposure-Level (1–5)</b></font>', ns)],
        [level_tbl],
    ], colWidths=[88 * mm])
    wrapper.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK SURFACE DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def _build_discovery_block(elements: List, styles: Dict) -> None:
    ns = styles.get("normal") or styles.get("Normal")

    elements.append(Paragraph(
        '<font size="9" color="#1A1A1A"><b>Attack Surface Discovery</b></font>', ns
    ))
    elements.append(Spacer(1, 6))

    items = [
        "DNS A/MX/NS-Records · crt.sh Zertifikats-Historie",
        "HackerTarget API — passiver Subdomain-Lookup",
        "CDN-Erkennung (Cloudflare, Akamai, Fastly, AWS)",
        "Kein Verbindungsaufbau zum Kundensystem",
    ]
    for item in items:
        elements.append(Paragraph(
            f'<font size="9" color="#444444">– {item}</font>', ns
        ))
        elements.append(Spacer(1, 3))