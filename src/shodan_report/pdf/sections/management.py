# ──────────────────────────────────────────────────────────────────────────────
# Management Section für PDF-Reports
# Generiert professionelle Management-Zusammenfassung im Security-Reporting-Stil
# ──────────────────────────────────────────────────────────────────────────────

from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from typing import List, Dict, Any
from reportlab.lib.units import mm

# ──────────────────────────────────────────────────────────────────────────────
# Management-Text & Insights Helpers
# ──────────────────────────────────────────────────────────────────────────────
from shodan_report.pdf.helpers.management_helpers import (
    extract_first_sentence,
    generate_priority_insights,
    generate_priority_recommendations,
)

# ──────────────────────────────────────────────────────────────────────────────
# PDF Helpers
# ──────────────────────────────────────────────────────────────────────────────
from shodan_report.pdf.helpers.pdf_helpers import build_horizontal_exposure_ampel


def create_management_section(
    elements: List,
    styles: Dict,
    management_text: str,
    technical_json: Dict[str, Any],
    evaluation,  # Kann dict ODER Evaluation Objekt sein
    business_risk: str,
    config: Dict[str, Any] = None
) -> None:
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
    
    config = config or {}

    # ──────────────────────────────────────────────────────────────────────────
    # 1. DATEN EXTRACTION - KOMPATIBEL MIT ALT UND NEU
    # ──────────────────────────────────────────────────────────────────────────
    
    # Extrahiere Exposure Score
    if isinstance(evaluation, dict):
        # NEUE VERSION: evaluation ist ein dict von runner.py
        exposure_score = evaluation.get("exposure_score", 1)
        exposure_display = evaluation.get("exposure_level", f"{exposure_score}/5")
        
        # Extrahiere und bereinige Risk Level
        risk_level_raw = evaluation.get("risk", "low")
        if isinstance(risk_level_raw, str):
            risk_level = risk_level_raw.lower()
            # Entferne "risklevel." Präfix falls vorhanden
            if "risklevel." in risk_level:
                risk_level = risk_level.replace("risklevel.", "")
        else:
            risk_level = str(risk_level_raw).lower()
            if "risklevel." in risk_level:
                risk_level = risk_level.replace("risklevel.", "")
        
        critical_points = evaluation.get("critical_points", [])
        critical_points_count = evaluation.get("critical_points_count", 0)
        cves = evaluation.get("cves", [])
        
    else:
        # ALTE VERSION: evaluation ist Evaluation Objekt
        exposure_score = getattr(evaluation, "exposure_level", 1)
        exposure_display = f"{exposure_score}/5"
        
        # Risk Level aus Evaluation Objekt
        risk_level_raw = getattr(evaluation, "risk", "low")
        if hasattr(risk_level_raw, 'value'):
            risk_level = risk_level_raw.value.lower()
        elif hasattr(risk_level_raw, 'name'):
            risk_level = risk_level_raw.name.lower()
        else:
            risk_level = str(risk_level_raw).lower()
            if "risklevel." in risk_level:
                risk_level = risk_level.replace("risklevel.", "")
        
        critical_points = getattr(evaluation, "critical_points", [])
        critical_points_count = len(critical_points)
        cves = getattr(evaluation, "cves", [])

    # ──────────────────────────────────────────────────────────────────────────
    # 2. ABSCHNITTS-TITEL
    # ──────────────────────────────────────────────────────────────────────────
    elements.append(Paragraph("1. Management-Zusammenfassung", styles["heading1"]))
    elements.append(Spacer(1, 12))

    # ──────────────────────────────────────────────────────────────────────────
    # 3. GESAMTBEWERTUNG & EXPOSURE-LEVEL (PROFESSIONELL)
    # ──────────────────────────────────────────────────────────────────────────
    elements.append(Paragraph("Gesamtbewertung der externen Angriffsfläche", styles["normal"]))
    elements.append(Spacer(1, 8))

    # Exposure-Level mit Beschreibung
    exposure_description_map = {
        1: "sehr niedrig",
        2: "niedrig–mittel", 
        3: "mittel",
        4: "hoch",
        5: "sehr hoch"
    }
    exposure_desc = exposure_description_map.get(exposure_score, "nicht bewertet")
    
    # Ampel visualisierung
    ampel = build_horizontal_exposure_ampel(exposure_score)

    elements.append(
        Table(
            [[
                Paragraph(
                    f"<b>Exposure-Level:</b> {exposure_score} von 5 ({exposure_desc})", 
                    styles["exposure"]
                ),
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
    elements.append(Spacer(1, 12))

    # ──────────────────────────────────────────────────────────────────────────
    # 4. PROFESSIONELLE EINLEITUNGSTEXTE
    # ──────────────────────────────────────────────────────────────────────────
    
    # Port-Anzahl aus technischen Daten
    open_ports = technical_json.get("open_ports", [])
    total_ports = len(open_ports) if open_ports else 0
    
    # CVE-Analyse
    cve_count = len(cves)
    
    # 4a. Erster Absatz: Faktenbasierte Einleitung
    intro_text = f"Auf Basis passiver OSINT-Daten wurden {total_ports} öffentlich erreichbare Dienste identifiziert."
    elements.append(Paragraph(intro_text, styles['normal']))
    elements.append(Spacer(1, 4))
    
    # 4b. Zweiter Absatz: CVE- und Risiko-Situation
    if cve_count == 0:
        cve_text = "Aktuell wurden keine kritisch ausnutzbaren Schwachstellen mit bekannter aktiver Exploit-Verfügbarkeit festgestellt."
    elif cve_count > 0:
        # Zeige konkrete Anzahl
        cve_text = f"Es wurden {cve_count} Sicherheitslücken identifiziert, wobei keine kritisch ausnutzbaren Schwachstellen (CVSS ≥ 9.0) mit bekannter Exploit-Verfügbarkeit vorliegen."
        elements.append(Paragraph(cve_text, styles['normal']))
        elements.append(Spacer(1, 4))
    
    # 4c. Dritter Absatz: Risiko-Einschätzung und Handlungsempfehlung
    if risk_level == "critical":
        risk_text = "Die externe Angriffsfläche weist kritische Sicherheitsprobleme auf, die sofortiges Handeln erfordern. Eine Priorisierung der Risikominimierung ist dringend empfohlen."
    elif risk_level == "high":
        risk_text = "Die externe Angriffsfläche zeigt erhebliche Sicherheitsrisiken, die zeitnahe Maßnahmen erfordern. Eine systematische Härtung der Konfigurationen wird empfohlen."
    elif risk_level == "medium":
        risk_text = "Die externe Angriffsfläche ist kontrolliert, jedoch bestehen strukturelle Risiken, die bei fehlender Härtung oder zukünftigen Schwachstellen zu einem erhöhten Risiko führen können."
    else:  # low
        risk_text = "Die externe Angriffsfläche ist gut kontrolliert und zeigt keine akuten Sicherheitsprobleme. Regelmäßige Überwachung wird zur Aufrechterhaltung des Sicherheitsniveaus empfohlen."
    
    elements.append(Paragraph(risk_text, styles['normal']))
    elements.append(Spacer(1, 12))

    # ──────────────────────────────────────────────────────────────────────────
    # 5. WICHTIGSTE ERKENNTNISSE (PROFESSIONELLE BULLET POINTS)
    # ──────────────────────────────────────────────────────────────────────────
    elements.append(Paragraph("<b>Wichtigste Erkenntnisse</b>", styles['normal']))
    elements.append(Spacer(1, 6))

    # Generiere Insights basierend auf Evaluationsdaten
    insights = generate_priority_insights(
        technical_json,
        evaluation,
        business_risk
    )
    
    # Fallback-Insights wenn keine generiert wurden
    if not insights:
        insights = _generate_fallback_insights(
            technical_json, 
            risk_level, 
            cve_count, 
            total_ports,
            critical_points
        )
    
    # Füge Insights als professionelle Bullet Points hinzu
    for insight in insights:
        elements.append(Paragraph(f"• {insight}", styles['bullet']))
        elements.append(Spacer(1, 2))
    
    elements.append(Spacer(1, 12))

    # ──────────────────────────────────────────────────────────────────────────
    # 6. EMPFEHLUNGEN AUF MANAGEMENT-EBENE
    # ──────────────────────────────────────────────────────────────────────────
    elements.append(Paragraph("<b>Empfehlung auf Management-Ebene</b>", styles['normal']))
    elements.append(Spacer(1, 6))

    # Generiere priorisierte Empfehlungen
    recommendations = generate_priority_recommendations(
        business_risk,
        technical_json,
        evaluation
    )
    
    # Fallback-Empfehlungen wenn keine generiert wurden
    if not recommendations:
        recommendations = _generate_fallback_recommendations(risk_level, business_risk)
    
    # Füge Empfehlungen als professionelle Bullet Points hinzu
    for rec in recommendations:
        elements.append(Paragraph(f"• {rec}", styles['bullet']))
        elements.append(Spacer(1, 2))
    
    # ──────────────────────────────────────────────────────────────────────────
    # 7. KRITISCHE PUNKTE DETAILS (nur wenn kritisch/high UND vorhanden)
    # ──────────────────────────────────────────────────────────────────────────
    if critical_points and risk_level in ["critical", "high"]:
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("<b>Details zu kritischen Punkten</b>", styles['normal']))
        elements.append(Spacer(1, 6))
        
        for i, point in enumerate(critical_points[:3], 1):  # Max. 3 anzeigen
            elements.append(Paragraph(f"{i}. {point}", styles['normal']))
            elements.append(Spacer(1, 4))
    
    elements.append(Spacer(1, 15))


# ──────────────────────────────────────────────────────────────────────────────
# INTERNE HELPER-FUNKTIONEN (nur für diese Datei)
# ──────────────────────────────────────────────────────────────────────────────

def _generate_fallback_insights(
    technical_json: Dict[str, Any],
    risk_level: str,
    cve_count: int,
    total_ports: int,
    critical_points: List[str]
) -> List[str]:
    """
    Generiert Fallback-Insights wenn keine von der Helper-Funktion geliefert werden.
    
    Returns:
        Liste mit professionellen Insights
    """
    insights = []
    
    # 1. Port- und Dienst-Informationen
    if total_ports > 0:
        insights.append(f"{total_ports} öffentliche Dienste sind konsistent erreichbar und stabil konfiguriert")
    
    # 2. CVE-Informationen
    if cve_count == 0:
        insights.append("Keine hochkritischen CVEs (CVSS ≥ 9.0) mit bekannter Exploit-Reife identifiziert")
    elif cve_count < 5:
        insights.append(f"{cve_count} Sicherheitslücken mit mittlerem bis niedrigem Risiko identifiziert")
    else:
        insights.append(f"{cve_count} Sicherheitslücken identifiziert - detaillierte Analyse im Anhang")
    
    # 3. Risiko-spezifische Insights
    if risk_level == "critical":
        if critical_points:
            insights.append(f"{len(critical_points)} kritische Sicherheitsprobleme erfordern sofortige Maßnahmen")
        insights.append("KRITISCHER Handlungsbedarf für Risikominimierung")
    elif risk_level == "high":
        insights.append("Erhöhter Handlungsbedarf für Sicherheitshärtung")
    
    # 4. Allgemeine Sicherheits-Insights
    insights.append("TLS-Konfiguration sollte auf aktuelle Standards überprüft werden")
    insights.append("Regelmäßige externe Sicherheitsscans werden empfohlen")
    
    return insights[:5]  # Maximal 5 Insights


def _generate_fallback_recommendations(risk_level: str, business_risk: str) -> List[str]:
    """
    Generiert Fallback-Empfehlungen basierend auf Risiko-Level.
    
    Returns:
        Liste mit professionellen Empfehlungen
    """
    
    business_risk_upper = str(business_risk).upper()
    
    # Kombiniere Business-Risiko mit Technical-Risiko für Empfehlungen
    if risk_level == "critical" or business_risk_upper == "CRITICAL":
        return [
            "SOFORT: Kritische Dienste isolieren oder Zugriff einschränken",
            "Innerhalb 24h: Incident Response Team aktivieren und Priorisierungs-Meeting durchführen",
            "Innerhalb 7 Tagen: Sicherheitsaudit und umfassende Härtungsmaßnahmen",
            "Mittelfristig: Etablierung eines kontinuierlichen Security-Monitorings"
        ]
    
    elif risk_level == "high" or business_risk_upper == "HIGH":
        return [
            "Innerhalb 7 Tagen: Detaillierte Sicherheitsanalyse durchführen",
            "Priorisierte Behebung der identifizierten Sicherheitsprobleme",
            "Kurzfristig: Härtung kritischer Konfigurationen",
            "Mittelfristig: Etablierung eines proaktiven Patch-Managements"
        ]
    
    elif risk_level == "medium" or business_risk_upper == "MEDIUM":
        return [
            "Keine sofortigen Notfallmaßnahmen erforderlich",
            "Innerhalb 30 Tagen: Geplante Sicherheitsupdates durchführen",
            "Regelmäßige Schwachstellenscans etablieren",
            "Security Awareness Training für verantwortliche Teams"
        ]
    
    else:  # low
        return [
            "Keine sofortigen Maßnahmen erforderlich",
            "Nächster Wartungszyklus: Geplante Sicherheitsüberprüfung",
            "Proaktive Überwachung der Angriffsfläche etablieren",
            "Regelmäßige Überprüfung der Sicherheitskonfigurationen"
        ]


# ──────────────────────────────────────────────────────────────────────────────
# ENDE DER DATEI
# ──────────────────────────────────────────────────────────────────────────────