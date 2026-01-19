# ──────────────────────────────────────────────────────────────────────────────
# Management Section für PDF-Reports
# Generiert professionelle Management-Zusammenfassung im Security-Reporting-Stil
# ──────────────────────────────────────────────────────────────────────────────

from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from typing import List, Dict, Any, Optional
from shodan_report.pdf.styles import Theme
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor

# ──────────────────────────────────────────────────────────────────────────────
# Management-Text & Insights Helpers
# ──────────────────────────────────────────────────────────────────────────────
from shodan_report.pdf.helpers.management_helpers import (
    extract_first_sentence,
    generate_priority_insights,
    generate_priority_recommendations,
    _sanitize_critical_point,
    _generate_fallback_insights,
    _generate_fallback_recommendations,
    _build_service_flags,
    _build_service_summary,
)
from .data.cve_enricher import enrich_cves_with_local


# ──────────────────────────────────────────────────────────────────────────────
# PDF Helpers
# ──────────────────────────────────────────────────────────────────────────────
from shodan_report.pdf.helpers.pdf_helpers import build_horizontal_exposure_ampel
from shodan_report.pdf.layout import keep_section, set_table_repeat, set_table_no_split
from .data.management_data import prepare_management_data
import re

def create_management_section(elements: List, styles: Dict, *args, **kwargs) -> None:
    """
    Erzeugt professionelle Management-Zusammenfassung im Security-Reporting-Stil.

    Args:
        elements: Liste der PDF-Elemente
        styles: ReportLab Stil-Definitionen
        management_text: Vorbereiteter Management-Text
        technical_json: Technische JSON-Daten aus Shodan
        evaluation: Evaluationsdaten (dict oder EvaluationResult)
        business_risk: Business-Risiko-Stufe
        config: Konfigurations-Parameter
    """

    # Support both DI-style call (elements, styles, theme, context=ctx)
    # and legacy call (elements=..., styles=..., management_text=..., technical_json=..., evaluation=..., business_risk=..., config=..., theme=...)
    config = {}
    theme = kwargs.get("theme", None)

    if "context" in kwargs and kwargs.get("context") is not None:
        ctx = kwargs["context"]
        management_text = getattr(ctx, "management_text", "")
        technical_json = getattr(ctx, "technical_json", {})
        evaluation = getattr(ctx, "evaluation", {})
        business_risk = getattr(ctx, "business_risk", "")
        config = getattr(ctx, "config", {}) or {}
    else:
        management_text = kwargs.get("management_text", "")
        technical_json = kwargs.get("technical_json", {})
        evaluation = kwargs.get("evaluation", {})
        business_risk = kwargs.get("business_risk", "")
        config = kwargs.get("config", {}) or {}

    # Extract canonical management data (keeps renderer thin and testable)
    mdata = prepare_management_data(technical_json, evaluation)
    exposure_score = mdata.get("exposure_score", 1)
    exposure_display = mdata.get("exposure_display", f"{exposure_score}/5")
    risk_level = mdata.get("risk_level", "low")
    critical_points = mdata.get("critical_points", [])
    critical_points_count = mdata.get("critical_points_count", 0)
    cves = mdata.get("cves", [])
    total_ports = mdata.get("total_ports", 0)
    cve_count = mdata.get("cve_count", 0)
    service_rows = mdata.get("service_rows", [])
    # ──────────────────────────────────────────────────────────────────────────
    # 2. ABSCHNITTS-TITEL
    # ──────────────────────────────────────────────────────────────────────────
    # Keep section header and the brief spacing together to avoid orphan headings
    elements.append(keep_section([Paragraph("1. Management-Zusammenfassung", styles["heading1"]), Spacer(1, 12)]))

    # ──────────────────────────────────────────────────────────────────────────
    # 3. GESAMTBEWERTUNG & EXPOSURE-LEVEL (PROFESSIONELL)
    # ──────────────────────────────────────────────────────────────────────────
    elements.append(
        Paragraph("Gesamtbewertung der externen Angriffsfläche", styles["normal"])
    )
    elements.append(Spacer(1, 8))

    # Exposure-Level mit Beschreibung
    exposure_description_map = {
        1: "sehr niedrig",
        2: "niedrig–mittel",
        3: "mittel",
        4: "hoch",
        5: "sehr hoch",
    }
    exposure_desc = exposure_description_map.get(exposure_score, "nicht bewertet")

    # Ampel visualisierung
    ampel = build_horizontal_exposure_ampel(exposure_score, theme=theme)

    exp_tbl = Table(
        [
            [
                Paragraph(
                    f"<b>Exposure-Level:</b> {exposure_score} von 5 ({exposure_desc})",
                    styles["exposure"],
                ),
                ampel,
            ]
        ],
        style=TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        ),
    )
    elements.append(exp_tbl)
    elements.append(Spacer(1, 12))
    # leave table as top-level element for test visibility

    # ──────────────────────────────────────────────────────────────────────────
    # 4. PROFESSIONELLE EINLEITUNGSTEXTE
    # ──────────────────────────────────────────────────────────────────────────

    # Use prepared management data (deduped CVEs, per-service attribution)
    open_ports = technical_json.get("open_ports", [])
    total_ports = mdata.get("total_ports", len(open_ports))
    cve_count = mdata.get("cve_count", 0)
    unique_cves = mdata.get("unique_cves", [])
    per_service = mdata.get("per_service", [])

    # 4a. Erster Absatz: Knackige Fakten
    intro_text = f"Auf Basis passiver OSINT-Daten wurden {total_ports} öffentlich erreichbare Dienste identifiziert."
    elements.append(Paragraph(intro_text, styles["normal"]))
    elements.append(Spacer(1, 4))

    # 4b. Zweiter Absatz: CVE- und Risiko-Situation
    if cve_count == 0:
        cve_text = "Keine kritisch ausnutzbaren, bekannten Schwachstellen festgestellt."
        elements.append(Paragraph(cve_text, styles["normal"]))
        elements.append(Spacer(1, 4))
    else:
        cve_text = f"Identifizierte Sicherheitslücken: {cve_count}. Weitere Details im Anhang."
        elements.append(Paragraph(cve_text, styles["normal"]))
        elements.append(Spacer(1, 4))

    # 4c. Dritter Absatz: Risiko-Einschätzung und Handlungsempfehlung
    if risk_level == "critical":
        risk_text = "Kritische Sicherheitsprobleme identifiziert. Sofortige Priorisierung empfohlen."
    elif risk_level == "high":
        risk_text = "Erhöhte Sicherheitsrisiken erkannt; zeitnahe Maßnahmen empfohlen."
    elif risk_level == "medium":
        risk_text = "Strukturelle Risiken vorhanden; Härtung und erweitertes Monitoring empfohlen."
    else:  # low
        risk_text = "Angriffsfläche überwiegend kontrolliert; regelmäßige Überprüfung empfohlen."

    elements.append(Paragraph(risk_text, styles["normal"]))
    elements.append(Spacer(1, 12))
    # Optional: kompakte Service-Tabelle für Management (Kurzüberblick)
    try:
        service_rows = _build_service_summary(technical_json)
    except Exception:
        service_rows = []

    if service_rows:
        elements.append(Paragraph("Kurzdetail zu betroffenen Diensten:", styles["normal"]))
        elements.append(Spacer(1, 6))
        # use Paragraph cells for wrapping and set reasonable column widths
        table_data = [[
            Paragraph("<b>Port</b>", styles["normal"]),
            Paragraph("<b>Dienst</b>", styles["normal"]),
            Paragraph("<b>Kurzbefund</b>", styles["normal"]),
            Paragraph("<b>Maßnahme</b>", styles["normal"]),
        ]]
        for port, prod, finding, action in service_rows:
            table_data.append([
                Paragraph(str(port), styles.get("normal")),
                Paragraph(prod or "-", styles.get("normal")),
                Paragraph(finding, styles.get("normal")),
                Paragraph(action, styles.get("normal")),
            ])

        # Align management table total width with the technical section table
        # (match total ~163 mm used in technical.py) so both appear uniform.
        tbl = Table(table_data, colWidths=[14 * mm, 55 * mm, 70 * mm, 24 * mm], repeatRows=1)
        set_table_no_split(tbl)
        tbl.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.2, (theme.muted if (theme and hasattr(theme, "muted")) else HexColor("#d1d5db"))),
                    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#f8fafc")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        # repeat header row and keep table together with spacer
        set_table_repeat(tbl, 1)
        set_table_no_split(tbl)
        elements.append(tbl)
        elements.append(Spacer(1, 12))
        # leave table as top-level element for test visibility

    # CVE overview removed from Management section per user request.

    # ──────────────────────────────────────────────────────────────────────────
    # 5. WICHTIGSTE ERKENNTNISSE (PROFESSIONELLE BULLET POINTS)
    # ──────────────────────────────────────────────────────────────────────────
    elements.append(Paragraph("<b>Wichtigste Erkenntnisse</b>", styles["normal"]))
    elements.append(Spacer(1, 6))

    # Generiere Insights basierend auf Evaluationsdaten
    insights = generate_priority_insights(technical_json, evaluation, business_risk)

    # Fallback-Insights wenn keine generiert wurden
    if not insights:
        insights = _generate_fallback_insights(
            technical_json, risk_level, cve_count, total_ports, critical_points
        )

    # Füge Insights als professionelle Bullet Points hinzu
    # Wenn die Insights keine echten `critical_points` enthalten (Evaluation liefert
    # keine), ersetzen wir generische "X kritische Risikopunkte" Formulierungen durch
    # eine weniger alarmierende Wortwahl: "X Dienste mit Sicherheits-Flags".
    processed_insights = []
    for insight in insights:
        # Ersetze nur wenn evaluation/critical_points leer sind
        if (
            isinstance(insight, str)
            and not critical_points
            and re.match(r"^\d+\s+kritische\s+Risikopunkte$", insight)
        ):
            swapped = re.sub(r"kritische\s+Risikopunkte", "Dienste mit Sicherheits-Flags", insight)
            processed_insights.append(swapped)
        else:
            processed_insights.append(insight)

    for insight in processed_insights:
        elements.append(Paragraph(f"• {insight}", styles["bullet"]))
        elements.append(Spacer(1, 2))

    elements.append(Spacer(1, 12))

    

    # ──────────────────────────────────────────────────────────────────────────
    # 6. EMPFEHLUNGEN AUF MANAGEMENT-EBENE
    # ──────────────────────────────────────────────────────────────────────────
    elements.append(
        Paragraph("<b>Empfehlung auf Management-Ebene</b>", styles["normal"])
    )
    elements.append(Spacer(1, 6))

    # Generiere priorisierte Empfehlungen
    recommendations = generate_priority_recommendations(
        business_risk, technical_json, evaluation
    )

    # Fallback-Empfehlungen wenn keine generiert wurden
    if not recommendations:
        recommendations = _generate_fallback_recommendations(risk_level, business_risk)

    # Füge Empfehlungen als professionelle Bullet Points hinzu
    for rec in recommendations:
        elements.append(Paragraph(f"• {rec}", styles["bullet"]))
        elements.append(Spacer(1, 2))

    # ──────────────────────────────────────────────────────────────────────────
    # 7. RISIKOHINWEISE (OSINT) DETAILS (nur wenn kritisch/high UND vorhanden)
    # ──────────────────────────────────────────────────────────────────────────
    if critical_points and risk_level in ["critical", "high"]:
        elements.append(Spacer(1, 12))
        elements.append(
            Paragraph("<b>Details zu Risikohinweisen (OSINT)</b>", styles["normal"])
        )
        elements.append(Spacer(1, 6))

        for i, point in enumerate(critical_points[:3], 1):  # Max. 3 anzeigen
            sanitized = _sanitize_critical_point(point)
            elements.append(Paragraph(f"{i}. {sanitized}", styles["normal"]))
            elements.append(Spacer(1, 4))

            # Versuche den kritischen Punkt mit technischen Diensten abzugleichen
            try:
                services = (technical_json.get("services") or []) if isinstance(technical_json, dict) else []
            except Exception:
                services = []

            matched = []
            for s in services:
                try:
                    port = s.get("port") if isinstance(s, dict) else getattr(s, "port", None)
                    prod = (s.get("product") if isinstance(s, dict) else getattr(s, "product", "")) or "unknown"
                    ver = (s.get("version") if isinstance(s, dict) else getattr(s, "version", "")) or ""
                    banner = (s.get("banner") if isinstance(s, dict) else getattr(s, "banner", "")) or ""
                    cves = s.get("cves") if isinstance(s, dict) else getattr(s, "cves", [])
                except Exception:
                    continue

                pt_lower = (point or "").lower()
                prod_l = (prod or "").lower()

                if (isinstance(port, int) and str(port) in pt_lower) or any(k in pt_lower for k in [prod_l, "ssh", "rdp", "http", "https", "nginx", "apache", "mysql"]):
                    matched.append((port, prod, ver, banner, cves))

            if matched:
                for (port, prod, ver, banner, cves) in matched:
                    line = f"- Port {port}: {prod} {ver}".strip()
                    if banner:
                        line += f"; Banner: {banner}"
                    if cves:
                        # normalize cve representations to simple ids
                        cve_ids = []
                        for cv in cves:
                            if isinstance(cv, dict):
                                cid = cv.get("id") or cv.get("cve")
                                if cid:
                                    cve_ids.append(str(cid))
                                    continue
                            cid = getattr(cv, "id", None) or getattr(cv, "cve", None)
                            if cid:
                                cve_ids.append(str(cid))
                            else:
                                cve_ids.append(str(cv))
                        line += f"; bekannte CVEs: {', '.join(cve_ids)}"
                    # kurze, prägnante Gegenmaßnahme
                    prod_l = (prod or "").lower()
                    if port == 22 or "ssh" in prod_l:
                        short = "z.B. Fail2Ban, SSH-Keys"
                    elif port in (80, 8080) or "http" in prod_l:
                        short = "z.B. HSTS, WAF"
                    elif port == 443 or "https" in prod_l:
                        short = "z.B. TLS≥1.2, starke Cipher"
                    else:
                        short = "Zugriffsregeln prüfen"

                    line += f"; Empfehlung: Zugangskontrollen und Patching prüfen; Kurz: {short}"
                    elements.append(Paragraph(line, styles["bullet"]))
                    elements.append(Spacer(1, 2))
            else:
                elements.append(Paragraph("- Keine direkten Service-Details im Snapshot gefunden; technische Bewertung empfohlen.", styles["bullet"]))
                elements.append(Spacer(1, 2))

    elements.append(Spacer(1, 15))





# ──────────────────────────────────────────────────────────────────────────────
# ENDE DER DATEI
# ──────────────────────────────────────────────────────────────────────────────
