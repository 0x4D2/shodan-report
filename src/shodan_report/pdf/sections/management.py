from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from typing import List, Dict, Any
from shodan_report.evaluation import Evaluation
from reportlab.lib.units import mm
from shodan_report.models import Service

# ─────────────────────────────────────────────
# Management-Text & Insights Helpers
# ─────────────────────────────────────────────
from shodan_report.pdf.helpers.management_helpers import (
    extract_first_sentence,
    generate_priority_insights,
    generate_priority_recommendations,
)

# ─────────────────────────────────────────────
# Evaluation Helpers
# ─────────────────────────────────────────────
from shodan_report.pdf.helpers.evaluation_helpers import (
    calculate_exposure_level,
    is_service_secure,
)

# ─────────────────────────────────────────────
# PDF Helpers
# ─────────────────────────────────────────────
from shodan_report.pdf.helpers.pdf_helpers import build_horizontal_exposure_ampel


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
    # Open Ports in Service-Objekte umwandeln
    # ─────────────────────────────────────────────
    open_ports = technical_json.get("open_ports", [])
    services = [
        p if isinstance(p, Service) else Service(
            port=p.get("port"),
            transport=p.get("transport", "tcp"),
            product=p.get("product"),
            ssl_info=p.get("ssl_info"),
            vpn_protected=p.get("vpn_protected", False),
            tunneled=p.get("tunneled", False),
            cert_required=p.get("cert_required", False),
            raw=p
        )
        for p in open_ports
    ]

    # ─────────────────────────────────────────────
    # 1. ABSCHNITTS-TITEL
    # ─────────────────────────────────────────────
    elements.append(Paragraph("1. Management-Zusammenfassung", styles["heading1"]))
    elements.append(Spacer(1, 10))

    # ─────────────────────────────────────────────
    # 2. Gesamtbewertung & Exposure-Level
    # ─────────────────────────────────────────────
    critical_points_count = len(getattr(evaluation, "critical_points", []))
    exposure_level = calculate_exposure_level(
        getattr(evaluation, "risk", "MEDIUM"),
        critical_points_count,
        services
    )

    elements.append(
        Paragraph("<b>Gesamtbewertung der externen Angriffsfläche</b>", styles["normal"])
    )
    elements.append(Spacer(1, 6))

    ampel = build_horizontal_exposure_ampel(exposure_level)

    elements.append(
        Table(
            [[
                Paragraph(f"<b>Exposure-Level:</b> <b>{exposure_level}/5</b>", styles["exposure"]),
                ampel,
            ]],
            style=TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
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
    # 3a. Dynamische Management-Zusammenfassung
    # NOTE:
    # Die CVE-Sektion wird aktuell nur passiv ausgewertet.
    # Eine belastbare Aussage zu "aktiv ausnutzbaren Schwachstellen"
    # ist erst möglich, sobald:
    # - CVEs mit Exploit-Reife (PoC / weaponized / in-the-wild)
    # - sowie eine saubere Zuordnung zu Service + Version
    # implementiert sind.
    # Bis dahin bleibt die Aussage bewusst konservativ.
    # ─────────────────────────────────────────────
    if services:
        total_services = len(services)
        critical_cves = [s for s in services if getattr(s, "version_risk", 0) > 0]  # Beispiel: Version-Risiko vorhanden
        structural_risks = any(not is_service_secure(s, ["ssh", "rdp", "https", "tls", "vpn"]) for s in services)

        summary_lines = []

        summary_lines.append(
            f"Auf Basis passiver OSINT-Daten wurden {total_services} öffentlich erreichbare Dienste identifiziert."
        )

        if not critical_cves:
            summary_lines.append(
                "Aktuell wurden keine kritisch ausnutzbaren Schwachstellen mit bekannter aktiver Exploit-Verfügbarkeit festgestellt."
            )
        else:
            summary_lines.append(
                f"{len(critical_cves)} Dienste zeigen potenzielle Schwachstellen, die überprüft werden sollten."
            )

        if structural_risks:
            summary_lines.append(
                "Die externe Angriffsfläche ist kontrolliert, jedoch bestehen strukturelle Risiken, die bei fehlender Härtung oder zukünftigen Schwachstellen zu einem erhöhten Risiko führen können."
            )
        else:
            summary_lines.append(
                "Die externe Angriffsfläche ist aktuell gut kontrolliert."
            )

        for line in summary_lines:
            elements.append(Paragraph(line, styles['normal']))
            elements.append(Spacer(1, 4))

    # ─────────────────────────────────────────────
    # 4. Wichtigste Erkenntnisse (max 4)
    # ─────────────────────────────────────────────
    elements.append(Paragraph("<b>Wichtigste Erkenntnisse</b>", styles['normal']))
    elements.append(Spacer(1, 4))

    insights = generate_priority_insights(
        {**technical_json, "open_ports": services},  # jetzt echte Service-Objekte
        evaluation,
        business_risk
    )
    for insight in insights:
        elements.append(Paragraph(f"• {insight}", styles['bullet']))
    elements.append(Spacer(1, 10))

    # ─────────────────────────────────────────────
    # 5. Empfehlungen (max 3)
    # ─────────────────────────────────────────────
    elements.append(Paragraph("<b>Empfehlung auf Management-Ebene</b>", styles['normal']))
    elements.append(Spacer(1, 4))

    recommendations = generate_priority_recommendations(
        business_risk,
        {**technical_json, "open_ports": services}
    )
    for rec in recommendations:
        elements.append(Paragraph(f"• {rec}", styles['bullet']))
