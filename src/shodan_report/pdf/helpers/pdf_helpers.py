from reportlab.platypus import Table, TableStyle
from reportlab.graphics.shapes import Drawing, Circle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import HexColor


# Farb-Palette pro Dot-Position (5 Dots, Gradient grün→orange→rot)
_AMPEL_DOT_COLORS = ["#22c55e", "#22c55e", "#f97316", "#dc2626", "#dc2626"]
_AMPEL_INACTIVE = "#d1d5db"


def build_horizontal_exposure_ampel(
    level: int,
    dot_size_mm: float = 3.2,
    spacing_mm: float = 1.8,
    theme=None,
) -> Drawing:
    """5-Dot-Ampel: die ersten `level` Dots leuchten auf (grün→orange→rot)."""
    n_dots = 5
    level = max(1, min(5, level))
    inactive = colors.HexColor(_AMPEL_INACTIVE)

    width = (dot_size_mm * n_dots + spacing_mm * (n_dots - 1)) * mm
    height = dot_size_mm * mm
    d = Drawing(width, height)

    for i in range(n_dots):
        color = colors.HexColor(_AMPEL_DOT_COLORS[i]) if i < level else inactive
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
