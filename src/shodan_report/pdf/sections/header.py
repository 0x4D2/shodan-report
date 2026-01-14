from reportlab.platypus import Paragraph, Spacer
from datetime import datetime
from typing import List, Dict, Any, Optional

from shodan_report.pdf.helpers.header_helpers import (
    generate_compact_report_id,
    format_assets_text,
    add_logo_to_elements,
)


def create_header_section(
    elements: List,
    styles: Dict,
    theme,  # Theme-Objekt wird jetzt wirklich genutzt
    customer_name: str,
    month: str,
    ip: str,
    config: Optional[Dict[str, Any]] = None,
    additional_assets: Optional[List[str]] = None,
) -> None:
    config = config or {}

    # ─────────────────────────────────────────────
    # Logo (optional)
    # ─────────────────────────────────────────────
    add_logo_to_elements(elements, config)

    # ─────────────────────────────────────────────
    # Titel
    # ─────────────────────────────────────────────
    elements.append(
        Paragraph(
            f"<b>SICHERHEITSREPORT</b><br/>{customer_name}",
            styles["title"].clone(
                "title_theme", textColor=theme.primary  # Theme Farbe nutzen
            ),
        )
    )

    # ─────────────────────────────────────────────
    # Datum formatieren
    # ─────────────────────────────────────────────
    try:
        report_date = datetime.strptime(month, "%Y-%m")
        month_formatted = report_date.strftime("%b %Y")
    except ValueError:
        month_formatted = month

    # Assets + Report-ID
    assets_text = format_assets_text(ip, additional_assets)
    report_id = generate_compact_report_id(customer_name, month, ip)

    # ─────────────────────────────────────────────
    # Meta-Zeile
    # ─────────────────────────────────────────────
    elements.append(
        Paragraph(
            f"<b>Scan:</b> {month_formatted} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Assets:</b> {assets_text} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Report-ID:</b> {report_id}",
            styles["meta"].clone("meta_theme", textColor=theme.secondary),
        )
    )

    elements.append(Spacer(1, 6))

    # ─────────────────────────────────────────────
    # Trennlinie
    # ─────────────────────────────────────────────
    elements.append(
        Paragraph(
            "<hr width='80%'/>",
            styles["normal"].clone("hr_theme", textColor=theme.muted),
        )
    )

    elements.append(Spacer(1, 10))


# Backward Compatibility
def _create_header(*args, **kwargs):
    return create_header_section(*args, **kwargs)
