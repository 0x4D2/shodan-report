from reportlab.platypus import Table, TableStyle
from reportlab.graphics.shapes import Drawing, Circle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import HexColor


def build_horizontal_exposure_ampel(
    level: int,
    dot_size_mm: float = 3.2,
    spacing_mm: float = 1.8,
    theme=None,
) -> Drawing:
    # Use centralized theme colors when provided, otherwise fall back to defaults
    success = getattr(theme, "success", colors.HexColor("#22c55e")) if theme else colors.HexColor("#22c55e")
    warn = getattr(theme, "warn", colors.HexColor("#f97316")) if theme else colors.HexColor("#f97316")
    danger = getattr(theme, "danger", colors.HexColor("#dc2626")) if theme else colors.HexColor("#dc2626")
    inactive = getattr(theme, "muted", colors.HexColor("#d1d5db")) if theme else colors.HexColor("#d1d5db")

    active_color = danger if level >= 4 else warn if level == 3 else success

    width = (dot_size_mm * 3 + spacing_mm * 2) * mm
    height = dot_size_mm * mm
    d = Drawing(width, height)
    colors_map = [
        success if active_color == success else inactive,
        warn if active_color == warn else inactive,
        danger if active_color == danger else inactive,
    ]

    for i, color in enumerate(colors_map):
        x = (dot_size_mm / 2 + i * (dot_size_mm + spacing_mm)) * mm
        y = (dot_size_mm / 2) * mm
        d.add(Circle(x, y, (dot_size_mm / 2) * mm, fillColor=color, strokeColor=color))

    return d


def clone_style_with_color(
    base_style: ParagraphStyle, text_color: str, name_suffix: str = "_colored"
) -> ParagraphStyle:
    return ParagraphStyle(
        name=f"{base_style.name}{name_suffix}",
        parent=base_style,
        textColor=HexColor(text_color),
    )
