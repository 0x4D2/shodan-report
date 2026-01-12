from reportlab.platypus import Paragraph, Spacer
from typing import List, Dict, Any
from shodan_report.evaluation import Evaluation
from reportlab.platypus import Table, TableStyle
from reportlab.lib.units import mm

from shodan_report.pdf.helpers.management_helpers import (
    get_exposure_color,
    extract_first_sentence,
    generate_priority_insights,
    calculate_exposure_level,
    generate_priority_recommendations,
    build_horizontal_exposure_ampel,
)


def create_management_section(
    elements: List,
    styles: Dict,
    management_text: str,
    technical_json: Dict[str, Any],
    evaluation: Evaluation,
    business_risk: str,
    config: Dict[str, Any] = None
) -> None:

    config = config or {}

    # ─────────────────────────────────────────────
    # Evaluation als Objekt sichern (falls dict übergeben)
    # ─────────────────────────────────────────────
    if isinstance(evaluation, dict):
        class EvaluationLike:
            def __init__(self, data):
                self.risk = data.get("risk", "MEDIUM")
                self.critical_points = data.get("critical_points", [])
                self.ip = data.get("ip", "")
                self.exposure_level = data.get("exposure_level", 2)
        evaluation = EvaluationLike(evaluation)


    # ─────────────────────────────────────────────
    # 1. ABSCHNITTS-TITEL
    # ─────────────────────────────────────────────
    elements.append(
        Paragraph("1. Management-Zusammenfassung", styles["heading1"])
    )
    elements.append(Spacer(1, 10))


    # ─────────────────────────────────────────────
    # 2. Gesamtbewertung & Exposure-Level
    # ─────────────────────────────────────────────
    exposure_level = calculate_exposure_level(
        getattr(evaluation, "risk", "MEDIUM"),
        getattr(evaluation, "critical_points", [])
    )

    elements.append(
        Paragraph(
            "<b>Gesamtbewertung der externen Angriffsfläche</b>",
            styles["normal"]
        )
    )
    elements.append(Spacer(1, 6))

    ampel = build_horizontal_exposure_ampel(exposure_level)

    elements.append(
        Table(
            [[
                Paragraph(
                    f"<b>Exposure-Level:</b> <b>{exposure_level}/5</b>",
                    styles["exposure"]
                ),
                ampel,
            ]],
          #  colWidths=[75*mm, 10*mm],
            style=TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
               # ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]),
        )
    )
    elements.append(Spacer(1, 8))

    # ─────────────────────────────────────────────
    # 3. Kernaussage (1–2 Sätze aus management_text)
    # ─────────────────────────────────────────────
    if management_text:
        first_sentence = extract_first_sentence(management_text)
        if first_sentence:
            elements.append(Paragraph(first_sentence, styles['normal']))
            elements.append(Spacer(1, 8))


    # ─────────────────────────────────────────────
    # 4. Wichtigste Erkenntnisse (max 4)
    # ─────────────────────────────────────────────
    elements.append(Paragraph("<b>Wichtigste Erkenntnisse</b>", styles['normal']))
    elements.append(Spacer(1, 4))

    insights = generate_priority_insights(technical_json, evaluation, business_risk)
    for insight in insights:
        elements.append(Paragraph(f"• {insight}", styles['bullet']))
    elements.append(Spacer(1, 10))


    # ─────────────────────────────────────────────
    # 5. Empfehlungen (max 3)
    # ─────────────────────────────────────────────
    elements.append(Paragraph("<b>Empfehlung auf Management-Ebene</b>", styles['normal']))
    elements.append(Spacer(1, 4))

    recommendations = generate_priority_recommendations(business_risk, technical_json, evaluation)
    for rec in recommendations:
        elements.append(Paragraph(f"• {rec}", styles['bullet']))




 
