# styles.py
from dataclasses import dataclass
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from typing import Dict


@dataclass(frozen=True)
class Theme:
    primary: HexColor
    secondary: HexColor
    muted: HexColor
    success: HexColor = HexColor("#22c55e")
    warn: HexColor = HexColor("#f97316")
    danger: HexColor = HexColor("#dc2626")


def create_theme(primary_hex: str, secondary_hex: str) -> Theme:
    return Theme(
        primary=HexColor(primary_hex),
        secondary=HexColor(secondary_hex),
        muted=HexColor("#d1d5db"),
        success=HexColor("#22c55e"),
        warn=HexColor("#f97316"),
        danger=HexColor("#dc2626"),
    )


def create_styles(theme: Theme) -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "Title",
            parent=base["Title"],
            fontSize=16,
            textColor=theme.primary,
            alignment=1,
            spaceAfter=12,
        ),
        "heading1": ParagraphStyle(
            "H1",
            parent=base["Heading1"],
            fontSize=12,
            textColor=theme.primary,
            spaceBefore=20,
            spaceAfter=6,
            borderColor=theme.primary,
            borderWidth=(0, 0, 1, 0),
        ),
        "heading2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontSize=11,
            textColor=theme.secondary,
            spaceBefore=12,
            spaceAfter=6,
        ),
        "normal": ParagraphStyle(
            "Normal",
            parent=base["Normal"],
            fontSize=10,
            leading=14,
        ),
        "exposure": ParagraphStyle(
            "Exposure",
            parent=base["Normal"],
            fontSize=10,
            leading=14,
            leftIndent=0,
            rightIndent=0,
            spaceBefore=0,
            spaceAfter=0,
        ),
        "bullet": ParagraphStyle(  # ✅ HIER IST DER FEHLER BEHOBEN
            "Bullet",
            parent=base["Normal"],
            fontSize=10,
            leftIndent=18,
            firstLineIndent=-9,
            spaceAfter=2,
            bulletIndent=9,
        ),
        "meta": ParagraphStyle(
            "Meta",
            parent=base["Normal"],
            fontSize=9,
            textColor=theme.secondary,
            alignment=1,
        ),
        "disclaimer": ParagraphStyle(
            "Disclaimer",
            parent=base["Normal"],
            fontSize=7,
            textColor=HexColor("#6b7280"),  # grau
            alignment=1,  # zentriert
            leading=10,
            spaceBefore=12,
            spaceAfter=6,
        ),
        "footer": ParagraphStyle(
            "Footer",
            parent=base["Normal"],
            fontSize=8,
            textColor=theme.secondary,
            alignment=1,
        ),
    }
