from typing import Any, Dict, List, Tuple

from reportlab.lib.colors import HexColor
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from shodan_report.pdf.layout import keep_section
from shodan_report.pdf.sections.data.executive_summary_data import prepare_executive_summary_data


_STATUS_LABELS = {
    "stable": ("Stabil", "#15803D"),
    "watch": ("Beobachten", "#B45309"),
    "action_required": ("Handlung erforderlich", "#B91C1C"),
}


def _status_table(styles: Dict[str, Any], status_key: str) -> Table:
    label, color = _STATUS_LABELS[status_key]
    table = Table(
        [[
            Paragraph('<font size="7" color="#6B7280">STATUS</font>', styles["normal"]),
            Paragraph(f'<font size="10" color="{color}"><b>{label}</b></font>', styles["normal"]),
        ]],
        colWidths=[22 * mm, 45 * mm],
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#F9FAFB")),
        ("BOX", (0, 0), (-1, -1), 0.6, HexColor(color)),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return table


def _info_box(title: str, lines: List[str], styles: Dict[str, Any], border: str) -> Table:
    rows = [[Paragraph(f'<font size="10" color="#111827"><b>{title}</b></font>', styles["normal"])]]
    for line in lines:
        rows.append([Paragraph(f'<font size="9" color="#374151">{line}</font>', styles["bullet"])])

    table = Table(rows, colWidths=[170 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#FFFFFF")),
        ("BOX", (0, 0), (-1, -1), 0.6, HexColor("#D1D5DB")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, HexColor(border)),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def create_executive_summary_section(elements: List, styles: Dict, *args, **kwargs) -> None:
    ctx = kwargs.get("context")
    if ctx is None:
        return

    data = prepare_executive_summary_data(ctx)

    section = [
        Paragraph("1. Kurzfassung &amp; Nächste Schritte", styles["heading1"]),
        Spacer(1, 8),
        _status_table(styles, data["status_key"]),
        Spacer(1, 10),
        _info_box("Kurzfassung", [data["summary_text"]], styles, "#2563EB"),
        Spacer(1, 10),
        _info_box("Was ist gut?", data["positive_points"], styles, "#15803D"),
        Spacer(1, 10),
    ]

    next_step_blocks = []
    for label, items, color in data["recommendation_groups"]:
        if not items:
            continue
        next_step_blocks.append(_info_box(label, items[:3], styles, color))
        next_step_blocks.append(Spacer(1, 8))

    if next_step_blocks:
        section.append(Paragraph("<b>Nächste Schritte</b>", styles["heading2"]))
        section.append(Spacer(1, 6))
        section.extend(next_step_blocks)

    elements.append(keep_section(section))