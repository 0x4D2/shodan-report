# styles.py
# ─────────────────────────────────────────────────────────────────────────────
# Professionelles PDF-Design — hell, druckbar, Audit-tauglich
# Farbgebung: Dunkelblau als Primary, Grautöne für Struktur, Akzentfarben
# nur für Risikostufen. Kein Cyan — das ist für die Webseite.
# ─────────────────────────────────────────────────────────────────────────────

from dataclasses import dataclass
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from typing import Dict


# ─────────────────────────────────────────────────────────────────────────────
# FARBPALETTE
# ─────────────────────────────────────────────────────────────────────────────

class Colors:
    # Primary — Dunkelblau (professionell, Audit-tauglich)
    primary      = HexColor("#1a365d")   # Dunkelblau — Überschriften, Akzente
    secondary    = HexColor("#2d4a7a")   # Mittelblau — Unterüberschriften
    accent       = HexColor("#1e56a0")   # Hellblau — Links, Highlights

    # Grautöne für Struktur
    text         = HexColor("#111827")   # Fast-Schwarz — Fließtext
    text_muted   = HexColor("#6b7280")   # Grau — Metadaten, Hinweise
    text_light   = HexColor("#9ca3af")   # Hellgrau — Fußnoten, Disclaimer
    border       = HexColor("#e5e7eb")   # Hellgrau — Tabellenlinien
    bg_light     = HexColor("#f8fafc")   # Fast-Weiß — Tabellen-Header
    bg_stripe    = HexColor("#f1f5f9")   # Sehr helles Grau — Zeilen-Zebra

    # Risikostufen — gesättigte Farben nur für Risiko-Kontext
    risk_critical_bg   = HexColor("#fef2f2")   # Hellrot Hintergrund
    risk_critical_text = HexColor("#991b1b")   # Dunkelrot Text
    risk_critical_dot  = HexColor("#dc2626")   # Rot Punkt/Badge

    risk_high_bg       = HexColor("#fff7ed")   # Hellorange Hintergrund
    risk_high_text     = HexColor("#9a3412")   # Dunkelorange Text
    risk_high_dot      = HexColor("#ea580c")   # Orange Punkt/Badge

    risk_medium_bg     = HexColor("#fefce8")   # Hellgelb Hintergrund
    risk_medium_text   = HexColor("#854d0e")   # Dunkelgelb Text
    risk_medium_dot    = HexColor("#ca8a04")   # Gelb Punkt/Badge

    risk_low_bg        = HexColor("#f0fdf4")   # Hellgrün Hintergrund
    risk_low_text      = HexColor("#166534")   # Dunkelgrün Text
    risk_low_dot       = HexColor("#16a34a")   # Grün Punkt/Badge

    risk_unknown_bg    = HexColor("#f9fafb")   # Sehr hell
    risk_unknown_text  = HexColor("#374151")
    risk_unknown_dot   = HexColor("#6b7280")

    white              = HexColor("#ffffff")


# ─────────────────────────────────────────────────────────────────────────────
# THEME DATACLASS (Kompatibilität mit bestehendem Code)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Theme:
    primary:   HexColor
    secondary: HexColor
    muted:     HexColor
    success:   HexColor = HexColor("#16a34a")
    warn:      HexColor = HexColor("#ea580c")
    danger:    HexColor = HexColor("#dc2626")


def create_theme(primary_hex: str, secondary_hex: str) -> Theme:
    return Theme(
        primary=HexColor(primary_hex),
        secondary=HexColor(secondary_hex),
        muted=HexColor("#9ca3af"),
        success=HexColor("#16a34a"),
        warn=HexColor("#ea580c"),
        danger=HexColor("#dc2626"),
    )


# Standard-Theme — wird überall verwendet wo kein Custom-Theme übergeben wird
DEFAULT_THEME = create_theme("#1a365d", "#2d4a7a")


# ─────────────────────────────────────────────────────────────────────────────
# STYLES
# ─────────────────────────────────────────────────────────────────────────────

def create_styles(theme: Theme = DEFAULT_THEME) -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    C = Colors

    return {

        # ── TITEL (Report-Header) ────────────────────────────────────────────
        "title": ParagraphStyle(
            "Title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=20,
            textColor=theme.primary,
            alignment=TA_CENTER,
            spaceAfter=6,
            leading=24,
        ),

        # ── ÜBERSCHRIFT 1 (Sektions-Titel) ──────────────────────────────────
        # Dunkelblauer Hintergrund-Streifen für klare visuelle Trennung
        "heading1": ParagraphStyle(
            "H1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=C.white,
            spaceBefore=18,
            spaceAfter=8,
            leftIndent=-6,
            rightIndent=-6,
            backColor=C.primary,
            borderPadding=(5, 6, 5, 6),
            leading=16,
        ),

        # ── ÜBERSCHRIFT 2 (Unter-Sektionen) ─────────────────────────────────
        "heading2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11,
            textColor=C.secondary,
            spaceBefore=12,
            spaceAfter=5,
            borderPadding=(0, 0, 3, 0),
            leading=14,
        ),

        # ── ÜBERSCHRIFT 3 (Tabellen-Titel etc.) ─────────────────────────────
        "heading3": ParagraphStyle(
            "H3",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=C.text,
            spaceBefore=8,
            spaceAfter=4,
            leading=13,
        ),

        # ── FLIESSTEXT ───────────────────────────────────────────────────────
        "normal": ParagraphStyle(
            "Normal",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=C.text,
            leading=13,
            spaceAfter=2,
        ),

        # ── BULLET-PUNKTE ────────────────────────────────────────────────────
        "bullet": ParagraphStyle(
            "Bullet",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=C.text,
            leftIndent=14,
            firstLineIndent=-8,
            spaceAfter=3,
            leading=13,
        ),

        # ── META-ZEILE (Report-ID, Datum etc.) ──────────────────────────────
        "meta": ParagraphStyle(
            "Meta",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=C.text_muted,
            alignment=TA_CENTER,
            leading=11,
            spaceAfter=2,
        ),

        # ── EXPOSURE-ANZEIGE ─────────────────────────────────────────────────
        "exposure": ParagraphStyle(
            "Exposure",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=C.text,
            leading=14,
            leftIndent=0,
            spaceAfter=0,
        ),

        # ── TABELLEN-HEADER TEXT ─────────────────────────────────────────────
        "table_header": ParagraphStyle(
            "TableHeader",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=C.text,
            leading=11,
            alignment=TA_LEFT,
        ),

        # ── TABELLEN-ZELLEN TEXT ─────────────────────────────────────────────
        "table_cell": ParagraphStyle(
            "TableCell",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=C.text,
            leading=11,
        ),

        # ── KLEINE SCHRIFT (Hinweise, Fußnoten) ──────────────────────────────
        "small": ParagraphStyle(
            "Small",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            textColor=C.text_muted,
            leading=10,
            spaceAfter=2,
        ),

        # ── DISCLAIMER / FOOTER-TEXT ─────────────────────────────────────────
        "disclaimer": ParagraphStyle(
            "Disclaimer",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            textColor=C.text_muted,
            alignment=TA_CENTER,
            leading=10,
            spaceBefore=8,
            spaceAfter=4,
        ),

        # ── FOOTER ───────────────────────────────────────────────────────────
        "footer": ParagraphStyle(
            "Footer",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            textColor=C.text_light,
            alignment=TA_CENTER,
            leading=10,
        ),

        # ── KENNZAHL-TITEL (in KPI-Tabellen) ────────────────────────────────
        "kpi_label": ParagraphStyle(
            "KpiLabel",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7,
            textColor=C.text_muted,
            alignment=TA_CENTER,
            leading=9,
            spaceAfter=1,
        ),

        # ── KENNZAHL-WERT (in KPI-Tabellen) ─────────────────────────────────
        "kpi_value": ParagraphStyle(
            "KpiValue",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=16,
            textColor=C.primary,
            alignment=TA_CENTER,
            leading=20,
        ),

        # ── RISIKO-KRITISCH ───────────────────────────────────────────────────
        "risk_critical": ParagraphStyle(
            "RiskCritical",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=C.risk_critical_text,
            leading=11,
        ),

        # ── RISIKO-HOCH ───────────────────────────────────────────────────────
        "risk_high": ParagraphStyle(
            "RiskHigh",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=C.risk_high_text,
            leading=11,
        ),

        # ── RISIKO-MITTEL ─────────────────────────────────────────────────────
        "risk_medium": ParagraphStyle(
            "RiskMedium",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=C.risk_medium_text,
            leading=11,
        ),

        # ── RISIKO-NIEDRIG ────────────────────────────────────────────────────
        "risk_low": ParagraphStyle(
            "RiskLow",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=C.risk_low_text,
            leading=11,
        ),
    }