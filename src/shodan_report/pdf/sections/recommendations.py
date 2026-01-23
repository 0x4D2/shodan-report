"""
Priorisierte Handlungsempfehlungen für PDF-Reports.
"""

from typing import List, Dict, Any
from reportlab.platypus import Spacer, Paragraph, ListFlowable, ListItem
from .data.recommendations_data import prepare_recommendations_data
from shodan_report.pdf.layout import keep_section

import typing


def create_recommendations_section(elements: List, styles: Dict, *args, **kwargs) -> None:
    # support DI via context or legacy args
    if "context" in kwargs and kwargs.get("context") is not None:
        ctx = kwargs.get("context")
        business_risk = getattr(ctx, "business_risk", "MEDIUM")
        technical_json = getattr(ctx, "technical_json", {})
        evaluation = getattr(ctx, "evaluation", {})
    else:
        business_risk = kwargs.get("business_risk")
        technical_json = kwargs.get("technical_json", {})
        evaluation = kwargs.get("evaluation", {})
    """
    Erstelle Section mit priorisierten Handlungsempfehlungen.

    Args:
        elements: Liste der PDF-Elemente
        styles: Dictionary mit PDF-Styles
        business_risk: Business Risk Level (HIGH/MEDIUM/LOW)
        technical_json: Technische Daten
        evaluation: Evaluation Ergebnisse
    """
    # keep header and following spacing together (avoid orphan heading)
    elements.append(keep_section([Paragraph("<b>2. Priorisierte Handlungsempfehlungen</b>", styles["heading1"]), Spacer(1, 12)]))

    # use prepared data for deterministic buckets
    buckets = prepare_recommendations_data(technical_json, evaluation, business_risk)

    # Priority 1
    elements.append(Paragraph("<b>Priorität 1 – Kritisch</b>", styles["normal"]))
    elements.append(Spacer(1, 6))
    priority1_items = buckets.get("priority1", [])
    if priority1_items:
        for item in priority1_items:
            elements.append(Paragraph(f"• {item}", styles["bullet"]))
    else:
        meta = buckets.get("meta", {}) or {}
        crit = meta.get("critical_cves", 0)
        tls_issues = meta.get("tls_issues", 0)
        if crit == 0 and tls_issues == 0:
            reason = "Keine Priorität-1-Maßnahmen aus OSINT ableitbar (keine kritischen CVEs/keine TLS-Schwachstellen in den Daten)."
        else:
            reason = "Keine Priorität-1-Maßnahmen aus OSINT ableitbar."
        elements.append(Paragraph(reason, styles["bullet"]))

    elements.append(Spacer(1, 8))

    # Priority 2
    if buckets.get("priority2"):
        elements.append(Paragraph("<b>Priorität 2 – Spezifische Empfehlungen</b>", styles["normal"]))
        elements.append(Spacer(1, 6))
        for item in buckets.get("priority2", []):
            elements.append(Paragraph(f"• {item}", styles["bullet"]))

    elements.append(Spacer(1, 8))

    # Priority 3
    if buckets.get("priority3"):
        elements.append(Paragraph("<b>Priorität 3 – Optional (Optimierung)</b>", styles["normal"]))
        elements.append(Spacer(1, 6))
        for item in buckets.get("priority3", []):
            elements.append(Paragraph(f"• {item}", styles["bullet"]))


def _extract_risk_level(business_risk) -> str:
    """Extrahiert Risiko-Level aus verschiedenen Input-Formaten."""
    if isinstance(business_risk, dict):
        return str(business_risk.get("level", "MEDIUM"))
    elif isinstance(business_risk, str):
        return business_risk
    else:
        return str(business_risk)


def _extract_port(port_info):
    """Extrahiert Port-Nummer aus verschiedenen Formaten."""
    if isinstance(port_info, dict):
        return port_info.get("port")
    else:
        return port_info  # port_info ist schon der Port (int)
