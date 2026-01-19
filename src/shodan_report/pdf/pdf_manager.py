# src/shodan_report/pdf/pdf_manager.py

from typing import List, Dict, Any, Optional, Callable

from .styles import create_theme, create_styles
from .sections.header import _create_header
from .context import ReportContext
from .layout import keep_section

from .sections.management import create_management_section
from .sections.technical import create_technical_section
from .sections.trend import create_trend_section
from .sections.footer import create_footer_section
from .sections.recommendations import create_recommendations_section
from .sections.methodology import create_methodology_section
from .sections.conclusion import create_conclusion_section
from .sections.cve_overview import create_cve_overview_section


def prepare_pdf_elements(
    customer_name: str,
    month: str,
    ip: str,
    management_text: str,
    trend_text: str,
    technical_json: Dict[str, Any],
    evaluation: Dict[str, Any],
    business_risk: str,
    config: Optional[Dict[str, Any]] = None,
    trend_table: Optional[Dict[str, Any]] = None,
    *,
    compare_month: Optional[str] = None,
    # Optional dependency-injection points for testability
    sections: Optional[List[Callable[..., None]]] = None,
) -> List:
    # ─────────────────────────────────────────────
    # Config & Theme
    # ─────────────────────────────────────────────
    config = config or {}
    styling = config.get("styling", {})

    primary_hex = styling.get("primary_color", "#1a365d")
    secondary_hex = styling.get("secondary_color", "#2d3748")

    theme = create_theme(primary_hex, secondary_hex)
    styles = create_styles(theme)

    elements: List = []

    # Build a ReportContext for sections to consume
    ctx = ReportContext(
        customer_name=customer_name,
        month=month,
        ip=ip,
        management_text=management_text,
        trend_text=trend_text,
        technical_json=technical_json,
        evaluation=evaluation,
        business_risk=business_risk,
        config=config,
        compare_month=compare_month,
        show_full_cve_list=config.get("show_full_cve_list", False),
        cve_limit=config.get("cve_limit", 6),
    )

    # If a `sections` list was provided, call each section callable in order.
    # Callables receive `elements`, `styles`, `theme`, and a `context` object.
    if sections is not None:
        for sec in sections:
            sec(elements=elements, styles=styles, theme=theme, context=ctx)
        return elements

    # Marker used to identify section starts. `render_pdf` will turn ranges
    # starting at this marker into a `KeepTogether` block before building.
    class _SectionMarker:
        pass

    if sections is not None:
        for sec in sections:
            sec(elements=elements, styles=styles, theme=theme, context=ctx)
        return elements

    # Default (legacy) behavior: call built-in section functions in order.
    # Insert a marker before each section so the renderer can keep the whole
    # section together when producing the PDF.
    elements.append(_SectionMarker())
    _create_header(elements=elements, styles=styles, theme=theme, customer_name=customer_name, month=month, ip=ip, config=config)

    # Do NOT insert a section marker between header and management — keep
    # header and the management summary together on the same page when
    # possible.
    create_management_section(elements=elements, styles=styles, management_text=management_text, technical_json=technical_json, evaluation=evaluation, business_risk=business_risk, config=config)

    # Section 3: Priorisierte Handlungsempfehlungen (directly after Management)
    create_recommendations_section(elements=elements, styles=styles, business_risk=business_risk, technical_json=technical_json, evaluation=evaluation)

    elements.append(_SectionMarker())
    create_technical_section(elements=elements, styles=styles, technical_json=technical_json, config=config)

    elements.append(_SectionMarker())
    create_cve_overview_section(elements=elements, styles=styles, technical_json=technical_json, evaluation=evaluation, context=ctx)

    elements.append(_SectionMarker())
    create_trend_section(elements=elements, styles=styles, trend_text=trend_text, compare_month=compare_month, trend_table=trend_table, legacy_mode=False, technical_json=technical_json, evaluation=evaluation)

    elements.append(_SectionMarker())
    create_methodology_section(elements=elements, styles=styles)

    elements.append(_SectionMarker())
    create_conclusion_section(elements=elements, styles=styles, customer_name=customer_name, business_risk=business_risk, context=ctx)

    # Keep Conclusion and Footer together — no marker between them so the
    # renderer will try to place them on the same page when possible.
    create_footer_section(elements=elements, styles=styles)

    return elements
