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
)

# ──────────────────────────────────────────────────────────────────────────────
# PDF Helpers
# ──────────────────────────────────────────────────────────────────────────────
from shodan_report.pdf.helpers.pdf_helpers import build_horizontal_exposure_ampel
import re


def create_management_section(
    elements: List,
    styles: Dict,
    management_text: str,
    technical_json: Dict[str, Any],
    evaluation: Any,
    business_risk: str,
    config: Dict[str, Any] = None,
    theme: Optional[Theme] = None,
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
        exposure_score = getattr(evaluation, "exposure_score", 1)
        exposure_display = f"{exposure_score}/5"

        # Risk Level aus Evaluation Objekt
        risk_level_raw = getattr(evaluation, "risk", "low")
        if hasattr(risk_level_raw, "value"):
            risk_level = risk_level_raw.value.lower()
        elif hasattr(risk_level_raw, "name"):
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

    elements.append(
        Table(
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
    )
    elements.append(Spacer(1, 12))

    # ──────────────────────────────────────────────────────────────────────────
    # 4. PROFESSIONELLE EINLEITUNGSTEXTE
    # ──────────────────────────────────────────────────────────────────────────

    # Port-Anzahl aus technischen Daten
    open_ports = technical_json.get("open_ports", [])
    total_ports = len(open_ports) if open_ports else 0

    # CVE-Analyse: dedupliziere CVE-IDs aus Evaluation und technischen Daten
    # support both legacy key 'vulns' and newer 'vulnerabilities'
    top_vulns = technical_json.get("vulns") or technical_json.get("vulnerabilities") or []
    # evaluation may be dict or object
    eval_cves = []
    if isinstance(evaluation, dict):
        eval_cves = evaluation.get("cves", []) or []
    else:
        eval_cves = getattr(evaluation, "cves", []) or []

    unique_cves = set()
    # include top-level vulns
    for v in list(top_vulns) + list(eval_cves):
        unique_cves.add(str(v))

    # include per-service vulnerabilities if present
    try:
        for svc in technical_json.get("open_ports", []) or []:
            if isinstance(svc, dict):
                sv_vulns = svc.get("vulnerabilities") or svc.get("_cves") or svc.get("vulns") or []
            else:
                sv_vulns = getattr(svc, "vulnerabilities", []) or getattr(svc, "_cves", []) or getattr(svc, "vulns", []) or []
            for vv in sv_vulns:
                unique_cves.add(str(vv))
    except Exception:
        pass

    cve_count = len(unique_cves)

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

        table_data = [["Port", "Dienst", "Kurzbefund", "Kurzmaßnahme"]]
        for port, prod, finding, action in service_rows:
            table_data.append([str(port), prod or "-", finding, action])

        tbl = Table(table_data, colWidths=[16 * mm, 50 * mm, 70 * mm, 36 * mm])
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

        elements.append(tbl)
        elements.append(Spacer(1, 12))

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
    # 7. KRITISCHE PUNKTE DETAILS (nur wenn kritisch/high UND vorhanden)
    # ──────────────────────────────────────────────────────────────────────────
    if critical_points and risk_level in ["critical", "high"]:
        elements.append(Spacer(1, 12))
        elements.append(
            Paragraph("<b>Details zu kritischen Punkten</b>", styles["normal"])
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
# INTERNE HELPER-FUNKTIONEN (nur für diese Datei)
# ──────────────────────────────────────────────────────────────────────────────


def _generate_fallback_insights(
    technical_json: Dict[str, Any],
    risk_level: str,
    cve_count: int,
    total_ports: int,
    critical_points: List[str],
) -> List[str]:
    """
    Generiert Fallback-Insights wenn keine von der Helper-Funktion geliefert werden.

    Returns:
        Liste mit professionellen Insights
    """
    insights = []

    # 1. Port- und Dienst-Informationen
    if total_ports > 0:
        insights.append(
            "Öffentliche Dienste sind konsistent erreichbar und stabil konfiguriert"
        )

    # 2. CVE-Informationen
    if cve_count == 0:
        insights.append(
            "Keine hochkritischen CVEs (CVSS ≥ 9.0) mit bekannter Exploit-Reife"
        )
    elif cve_count < 5:
        insights.append(f"{cve_count} Sicherheitslücken mit mittlerem bis niedrigem Risiko identifiziert")
    else:
        insights.append(f"{cve_count} Sicherheitslücken identifiziert – detaillierte Analyse im Anhang")

    # 3. Struktur- und Konfigurationshinweise
    structural_risk = False
    open_ports = technical_json.get("open_ports", []) or []
    for svc in open_ports:
        try:
            if getattr(svc, "version_risk", 0) > 0 or getattr(svc, "_version_risk", 0) > 0:
                structural_risk = True
                break
        except Exception:
            continue

    if structural_risk:
        insights.append("TLS-Konfiguration teilweise veraltet oder unvollständig")
    elif len(open_ports) > 0:
        insights.append("Einige Dienste zeigen unsichere Konfigurationen, Härtung empfohlen")

    # 4. Monitoring-Empfehlung als Standard
    insights.append("Regelmäßige externe Sicherheitsscans und Monitoring werden empfohlen")

    return insights[:5]


def _generate_fallback_recommendations(
    risk_level: str, business_risk: str
) -> List[str]:
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
            "Mittelfristig: Etablierung eines kontinuierlichen Security-Monitorings",
        ]

    elif risk_level == "high" or business_risk_upper == "HIGH":
        return [
            "Innerhalb 7 Tagen: Detaillierte Sicherheitsanalyse durchführen",
            "Priorisierte Behebung der identifizierten Sicherheitsprobleme",
            "Kurzfristig: Härtung kritischer Konfigurationen",
            "Mittelfristig: Etablierung eines proaktiven Patch-Managements",
        ]

    elif risk_level == "medium" or business_risk_upper == "MEDIUM":
        return [
            "Keine sofortigen Notfallmaßnahmen erforderlich",
            "Innerhalb 30 Tagen: Geplante Sicherheitsupdates durchführen",
            "Regelmäßige Schwachstellenscans etablieren",
            "Security Awareness Training für verantwortliche Teams",
        ]

    else:  # low
        return [
            "Keine sofortigen Maßnahmen erforderlich",
            "Nächster Wartungszyklus: Geplante Sicherheitsüberprüfung",
            "Proaktive Überwachung der Angriffsfläche etablieren",
            "Regelmäßige Überprüfung der Sicherheitskonfigurationen",
        ]
 

def _build_service_flags(technical_json: Dict[str, Any]) -> List[str]:
    """
    Extrahiert kurze, lesbare Flags aus den `technical_json` Services.
    Die Funktion verwendet einfache Heuristiken basierend auf verfügbaren
    Feldern wie `services[].port`, `product`, `version`, sowie Top-Level
    `ssl_info`.
    """
    flags: List[str] = []
    # Support both legacy `services` and new `open_ports` formats
    services = technical_json.get("services") or []
    if not services and technical_json.get("open_ports"):
        services = []
        for p in technical_json.get("open_ports", []):
            if isinstance(p, dict):
                port = p.get("port")
                product = p.get("service", {}).get("product") if isinstance(p.get("service"), dict) else None
                version = p.get("service", {}).get("version") if isinstance(p.get("service"), dict) else None
                banner = p.get("service", {}).get("banner") if isinstance(p.get("service"), dict) else None
            else:
                port = getattr(p, "port", None)
                product = getattr(p, "product", None)
                version = getattr(p, "version", None)
                # raw may contain parsed banner info
                banner = getattr(p, "raw", None)

            services.append({"port": port, "product": product, "version": version, "banner": banner})
    # top-level ssl presence
    has_ssl_info = bool(technical_json.get("ssl_info"))

    for svc in services:
        try:
            port = svc.get("port") if isinstance(svc, dict) else getattr(svc, "port", None)
            prod = (svc.get("product") if isinstance(svc, dict) else getattr(svc, "product", "")) or ""
            ver = (svc.get("version") if isinstance(svc, dict) else getattr(svc, "version", "")) or ""
            prod_l = prod.lower()

            if port == 22 or "ssh" in prod_l:
                # SSH: Banner sichtbar -> prüfe Auth/RootLogin/Fail2Ban
                summary = f"Port {port}: SSH ({prod} {ver.split()[0] if ver else ''}) - Banner sichtbar; prüfen: Passwort-Authentifizierung, Root-Login und Schutzmechanismen"
                flags.append(summary)
                continue

            # Prefer TLS/HTTPS note for port 443 regardless of product banner
            if port == 443 or "https" in prod_l:
                # HTTPS: TLS Hinweise
                tls_note = f"Port {port}: HTTPS - Zertifikat/Chain prüfen; HSTS/OCSP prüfen; (ssl_info vorhanden: {'ja' if has_ssl_info else 'nein'})"
                flags.append(tls_note)
                continue

            if port in (80, 8080) or "http" in prod_l:
                # HTTP: Server-Banner / Default-Seite Hinweise
                note = f"Port {port}: HTTP ({'nginx' if 'nginx' in ver.lower() or 'nginx' in prod_l else prod}) - Server-Banner sichtbar; prüfen: Default-Seiten, Härtung und Sicherheits-Header"
                flags.append(note)
                continue

            # Generic fallback for other services
            if prod:
                flags.append(f"Port {port}: {prod} — weitere Prüfung empfohlen")
        except Exception:
            continue

    # Deduplicate and limit to 6 lines
    seen = []
    out = []
    for f in flags:
        if f not in seen:
            seen.append(f)
            out.append(f)
        if len(out) >= 6:
            break
    return out


def _build_service_summary(technical_json: Dict[str, Any]) -> List[tuple]:
    """
    Liefert strukturierte, kurze Zusammenfassungszeilen für die Tabelle:
    (port, product, finding, short_action). Sortiert nach Schweregrad.
    """
    services = technical_json.get("services") or []
    if not services and technical_json.get("open_ports"):
        services = []
        for p in technical_json.get("open_ports", []):
            if isinstance(p, dict):
                port = p.get("port")
                product = p.get("service", {}).get("product") if isinstance(p.get("service"), dict) else p.get("product")
                version = p.get("service", {}).get("version") if isinstance(p.get("service"), dict) else p.get("version")
            else:
                port = getattr(p, "port", None)
                product = getattr(p, "product", None)
                version = getattr(p, "version", None)
            services.append({"port": port, "product": product, "version": version})

    # Build candidate rows with a simple severity heuristic
    rows = []
    critical_list = technical_json.get("critical_services") or []
    vuln_list = technical_json.get("vulnerable_versions") or []

    for s in services:
        try:
            port = s.get("port") if isinstance(s, dict) else getattr(s, "port", None)
            prod = (s.get("product") if isinstance(s, dict) else getattr(s, "product", "")) or "-"
            ver = (s.get("version") if isinstance(s, dict) else getattr(s, "version", "")) or ""
        except Exception:
            continue

        prod_l = (prod or "").lower()
        # Determine finding and short action
        if port == 22 or "ssh" in prod_l:
            finding = "SSH Service - Banner sichtbar"
            action = "Fail2Ban; SSH-Keys"
        elif port in (80, 8080) or "http" in prod_l:
            finding = "HTTP Service - Server-Banner / No HSTS"
            action = "HSTS; WAF"
        elif port == 443 or "https" in prod_l:
            finding = "HTTPS Service - Zertifikat/Chain prüfen"
            action = "TLS>=1.2; starke Cipher"
        else:
            finding = "Öffentlicher Dienst"
            action = "Zugriffsregeln prüfen"

        # severity: 2 = critical, 1 = vulnerable, 0 = info
        severity = 0
        for c in critical_list:
            if c.get("port") == port:
                severity = max(severity, 2)
        for v in vuln_list:
            if v.get("port") == port:
                severity = max(severity, 1)

        rows.append((severity, port, prod, finding, action))

    # sort by severity desc, then port
    rows_sorted = sorted(rows, key=lambda x: (-x[0], x[1] or 0))
    # return tuples without severity
    return [(r[1], r[2], r[3], r[4]) for r in rows_sorted]


# ──────────────────────────────────────────────────────────────────────────────
# ENDE DER DATEI
# ──────────────────────────────────────────────────────────────────────────────
