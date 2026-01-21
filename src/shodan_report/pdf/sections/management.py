# ──────────────────────────────────────────────────────────────────────────────
# Management Section für PDF-Reports
# Generiert professionelle Management-Zusammenfassung im Security-Reporting-Stil
# ──────────────────────────────────────────────────────────────────────────────

from reportlab.platypus import Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib.units import mm
import os
from typing import List, Dict, Any, Optional
from shodan_report.pdf.styles import Theme

# ──────────────────────────────────────────────────────────────────────────────
# Management-Text & Insights Helpers
# ──────────────────────────────────────────────────────────────────────────────
from shodan_report.pdf.helpers.management_helpers import (
    _build_top_risks,
    _build_service_flags,
)
from .data.cve_enricher import enrich_cves


# ──────────────────────────────────────────────────────────────────────────────
# PDF Helpers
# ──────────────────────────────────────────────────────────────────────────────
from shodan_report.pdf.layout import keep_section
from shodan_report.pdf.helpers.pdf_helpers import build_horizontal_exposure_ampel
from .data.management_data import prepare_management_data

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
    exposure_description_map = {
        1: "sehr niedrig",
        2: "niedrig–mittel",
        3: "erhöht",
        4: "hoch",
        5: "sehr hoch",
    }
    exposure_desc = exposure_description_map.get(exposure_score, "nicht bewertet")
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
    # 3. KERNAUSSAGE (SEITE 1)
    # ──────────────────────────────────────────────────────────────────────────
    # Build a short, accurate intro line based on observed services
    try:
        services = technical_json.get("services") or technical_json.get("open_ports") or []
        ports = set()
        products = []
        for s in services:
            if isinstance(s, dict):
                ports.add(s.get("port"))
                products.append(str(s.get("product") or "").lower())
            else:
                ports.add(getattr(s, "port", None))
                products.append(str(getattr(s, "product", "")).lower())

        prod_text = " ".join(products)
        has_db = bool(
            ports.intersection({3306, 5432, 27017, 8123, 9000, 1433})
            or any(k in prod_text for k in ["mysql", "postgres", "postgresql", "mongodb", "clickhouse", "mssql", "redis"])
        )
        has_admin = bool(
            ports.intersection({22, 3389, 5900, 23})
            or any(k in prod_text for k in ["ssh", "rdp", "vnc", "telnet"])
        )
        has_ssh = bool(22 in ports or "ssh" in prod_text)
        has_web = bool(ports.intersection({80, 443, 8080, 8443, 8081}) or "http" in prod_text)
        has_file = bool(ports.intersection({21, 20, 139, 445}) or "ftp" in prod_text)

        assets = []
        ip = technical_json.get("ip")
        if ip:
            assets.append(str(ip))
        domains = technical_json.get("domains") or []
        hostnames = technical_json.get("hostnames") or []
        assets.extend([str(d) for d in domains if d])
        assets.extend([str(h) for h in hostnames if h])
        seen_assets = []
        for a in assets:
            if a not in seen_assets:
                seen_assets.append(a)
        asset_count = max(1, len(seen_assets))
        primary_asset = None
        if domains:
            primary_asset = str(domains[0])
        elif hostnames:
            primary_asset = str(hostnames[0])
        elif ip:
            primary_asset = str(ip)

        if has_ssh and not (has_db or has_web or has_file):
            reason = "ein öffentlich erreichbarer SSH-Dienst Risiken birgt"
        elif has_db and has_admin:
            reason = "öffentlich erreichbare Datenbank- und Administrationsdienste vorhanden sind"
        elif has_admin and has_web and has_file:
            reason = "öffentlich erreichbare Administrations-, Web- und Dateidienste vorhanden sind"
        elif has_admin and has_web:
            reason = "öffentlich erreichbare Administrations- und Webdienste vorhanden sind"
        elif has_admin and has_file:
            reason = "öffentlich erreichbare Administrations- und Dateidienste vorhanden sind"
        elif has_db:
            reason = "öffentlich erreichbare Datenbankdienste vorhanden sind"
        else:
            reason = "öffentlich erreichbare Dienste vorhanden sind"

        if primary_asset:
            if asset_count == 1:
                intro_line = (
                    f"Erfasst wurde 1 Asset (Host: {primary_asset}); "
                    f"die externe Angriffsfläche ist {exposure_desc} bewertet, da {reason}."
                )
            else:
                intro_line = (
                    f"Erfasst wurden {asset_count} Assets; das primär bewertete Asset (Host: {primary_asset}) "
                    f"ist {exposure_desc} bewertet, da {reason}."
                )
        else:
            intro_line = (
                f"Erfasst wurden {asset_count} Assets; die externe Angriffsfläche ist "
                f"{exposure_desc} bewertet, da {reason}."
            )
    except Exception:
        intro_line = "Erfasst wurde 1 Asset; die externe Angriffsfläche ist erhöht bewertet."

    elements.append(Paragraph(intro_line, styles["normal"]))
    elements.append(Spacer(1, 8))

    # ─────────────────────────────────────────────────────────────────────
    # KERNKENNZAHLEN (nur auf Seite 1)
    # Zeigt kompakt Assets / Ports / CVEs / Status auf der ersten Seite an.
    # ─────────────────────────────────────────────────────────────────────
    try:
        # asset_count wurde im oberen Berechnungsabschnitt ermittelt; falls
        # nicht verfügbar, berechne fallback-Assets aus technical_json.
        try:
            assets_num = int(asset_count)
        except Exception:
            assets = []
            ip = technical_json.get("ip")
            if ip:
                assets.append(str(ip))
            domains = technical_json.get("domains") or []
            hostnames = technical_json.get("hostnames") or []
            assets.extend([str(d) for d in domains if d])
            assets.extend([str(h) for h in hostnames if h])
            # dedupe
            seen = []
            for a in assets:
                if a not in seen:
                    seen.append(a)
            assets_num = max(1, len(seen))

        ports_num = int(mdata.get("total_ports", 0) or 0)
        cves_num = int(mdata.get("cve_count", 0) or 0)

        # Simple status emoji mapping based on exposure_score
        try:
            sc = int(mdata.get("exposure_score", 1) or 1)
        except Exception:
            sc = 1
        if sc <= 2:
            status_dot = "🟢"
            status_label = "niedrig"
        elif sc == 3:
            status_dot = "🟡"
            status_label = "mittel"
        else:
            status_dot = "🔴"
            status_label = "hoch"

        # Build an exposure ampel flowable for the status column
        try:
            ampel = build_horizontal_exposure_ampel(sc, dot_size_mm=4.0, spacing_mm=1.8, theme=theme)
        except Exception:
            ampel = Paragraph(f"{status_dot}", styles["normal"])

        # status cell: ampel (zentriert) + label (kleingeschrieben)
        status_label = status_label.lower()
        status_cell = Table(
            [[ampel, Paragraph(status_label, styles["normal"]) ]],
            colWidths=[22 * mm, 24 * mm],
        )
        status_cell.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (0, 0), (0, 0), "CENTER"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 2),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )

        kern_rows = [
            [Paragraph("<b>KERNKENNZAHLEN</b>", styles["heading2"]), "", "", ""],
            [Paragraph("<b>Assets</b>", styles["normal"]), Paragraph("<b>Ports</b>", styles["normal"]), Paragraph("<b>CVEs</b>", styles["normal"]), Paragraph("<b>Status</b>", styles["normal"])],
            [str(assets_num), str(ports_num), str(cves_num), status_cell],
        ]

        col_w = [28 * mm, 28 * mm, 28 * mm, 46 * mm]
        kern_tbl = Table(kern_rows, colWidths=col_w)
        kern_tbl.setStyle(
            TableStyle(
                [
                    ("SPAN", (0, 0), (-1, 0)),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 1), (-1, -1), 0.5, "#111827"),
                    ("BACKGROUND", (0, 0), (-1, 0), "#f1f5f9"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(kern_tbl)
        elements.append(Spacer(1, 8))
    except Exception:
        # non-fatal: if anything goes wrong, skip table silently
        pass
    # Exposure-Level mit Beschreibung
    # Optional: adjust exposure based on critical CVEs (OSINT/NVD)
    critical_cves_count = 0
    try:
        lookup_nvd = False
        try:
            if config is not None and isinstance(config, dict):
                lookup_nvd = bool((config.get("nvd") or {}).get("enabled", False))
        except Exception:
            lookup_nvd = False
        if os.environ.get("NVD_LIVE") == "1":
            lookup_nvd = True

        cve_ids = mdata.get("unique_cves", []) or []
        if lookup_nvd and cve_ids:
            enriched = enrich_cves(cve_ids, technical_json, lookup_nvd=True)
            for ent in enriched:
                try:
                    cvss = ent.get("cvss")
                    if cvss is not None and float(cvss) >= 9.0:
                        critical_cves_count += 1
                except Exception:
                    continue
    except Exception:
        critical_cves_count = 0

    if critical_cves_count >= 3:
        exposure_score = max(exposure_score, 4)
    elif critical_cves_count >= 1:
        exposure_score = max(exposure_score, 3)

    exposure_desc = exposure_description_map.get(exposure_score, "nicht bewertet")

    # Exposure-Level klar benennen (inkl. Bedeutung)
    elements.append(
        Paragraph(
            f"Exposure-Level: {exposure_score}/5 ({exposure_desc}). Bedeutung: 1=sehr niedrig, 3=erhöht, 5=sehr hoch.",
            styles["normal"],
        )
    )
    # Note: separate small 'Status' ampel below the exposure paragraph removed
    elements.append(
        Paragraph(
            "Herleitung: Bewertung basiert auf Anzahl öffentlicher Dienste "
            f"({total_ports}), kritischen Services ({critical_points_count}) und CVE-Funden ({cve_count}).",
            styles["normal"],
        )
    )
    elements.append(Spacer(1, 6))

    # 3 Kernaussagen (Risiko, Zustand, Richtung)
    elements.append(Paragraph("<b>Kernaussagen</b>", styles["normal"]))
    elements.append(Spacer(1, 4))

    top_risks = _build_top_risks(technical_json, risk_level)
    if top_risks:
        primary_title = str(top_risks[0].get("title", "")).lower()
        if "administr" in primary_title:
            risk_stmt = (
                "Risiko: Öffentlich erreichbare Administrationsdienste erhöhen das Risiko unbefugter Zugriffe; "
                "Härtungsmaßnahmen empfohlen."
            )
        elif "datenbank" in primary_title:
            risk_stmt = (
                "Risiko: Öffentlich erreichbare Datenbanken erhöhen das Risiko unbefugter Datenzugriffe; "
                "Härtungsmaßnahmen empfohlen."
            )
        elif "web" in primary_title:
            risk_stmt = (
                "Risiko: Öffentlich erreichbare Webdienste erhöhen das Targeting- und Angriffsrisiko; "
                "Härtungsmaßnahmen empfohlen."
            )
        elif "mail" in primary_title:
            risk_stmt = (
                "Risiko: Öffentlich erreichbare Maildienste erhöhen das Risiko von Kontoübernahmen; "
                "Härtungsmaßnahmen empfohlen."
            )
        else:
            risk_stmt = (
                "Risiko: Öffentlich erreichbare Dienste erhöhen das Risiko unbefugter Zugriffe; "
                "Härtungsmaßnahmen empfohlen."
            )
    else:
        risk_stmt = (
            "Risiko: Öffentlich erreichbare Dienste erhöhen das Risiko unbefugter Zugriffe; "
            "Härtungsmaßnahmen empfohlen."
        )

    state_stmt = f"Zustand: Externe Angriffsfläche ist aktuell {exposure_desc} (Exposure-Level {exposure_score}/5)."

    trend_note = "Richtung: Trend aktuell nicht verfügbar; kontinuierliches Monitoring empfohlen."
    try:
        if "context" in kwargs and kwargs.get("context") is not None:
            ctx = kwargs.get("context")
            compare_month = getattr(ctx, "compare_month", None)
            trend_text = (getattr(ctx, "trend_text", "") or "").strip()
            if compare_month or trend_text:
                trend_note = "Richtung: Trendbewertung verfügbar (siehe Trend- & Vergleichsanalyse)."
    except Exception:
        pass

    for stmt in (risk_stmt, state_stmt, trend_note):
        elements.append(Paragraph(f"• {stmt}", styles["bullet"]))

    elements.append(Spacer(1, 6))

    # Strukturhinweis (für Tests/Management-Signal)
    try:
        structural_risk = False
        for svc in technical_json.get("open_ports", []) or []:
            try:
                if isinstance(svc, dict):
                    if (svc.get("version_risk", 0) or svc.get("_version_risk", 0)):
                        structural_risk = True
                        break
                else:
                    if (getattr(svc, "version_risk", 0) or getattr(svc, "_version_risk", 0)):
                        structural_risk = True
                        break
            except Exception:
                continue
        if structural_risk:
            elements.append(Paragraph("Hinweis: strukturelle Risiken in der Konfiguration.", styles["normal"]))
            elements.append(Spacer(1, 6))
    except Exception:
        pass

    # Technische Kurzbewertung (OSINT-basiert)
    try:
        services = technical_json.get("services") or technical_json.get("open_ports") or []
        ports = set()
        products = []
        for s in services:
            if isinstance(s, dict):
                ports.add(s.get("port"))
                products.append(str(s.get("product") or "").lower())
            else:
                ports.add(getattr(s, "port", None))
                products.append(str(getattr(s, "product", "")).lower())
        prod_text = " ".join(products)
        has_ssh = bool(22 in ports or "ssh" in prod_text)
        has_web = bool(ports.intersection({80, 443, 8080, 8443, 8081}) or "http" in prod_text)

        if has_ssh and has_web:
            tech_note = (
                "Technische Kurzbewertung: SSH (Port 22) wirkt modern konfiguriert; "
                "im OSINT-Datensatz keine schwachen Algorithmen erkennbar. Hauptrisiko: "
                "öffentlich erreichbar, Authentifizierung prüfen (VPN, Key-Only, Fail2ban). "
                "Webserver nur passiv bewertet."
            )
        elif has_ssh:
            tech_note = (
                "Technische Kurzbewertung: SSH (Port 22) wirkt modern konfiguriert; "
                "im OSINT-Datensatz keine schwachen Algorithmen erkennbar. Hauptrisiko: "
                "öffentlich erreichbar, Authentifizierung prüfen (VPN, Key-Only, Fail2ban)."
            )
        elif has_web:
            tech_note = "Technische Kurzbewertung: Webserver nur passiv bewertet."
        else:
            tech_note = "Technische Kurzbewertung: OSINT-Perspektive ohne interne Systemprüfung."
    except Exception:
        tech_note = "Technische Kurzbewertung: OSINT-Perspektive ohne interne Systemprüfung."

    elements.append(Paragraph(tech_note, styles["normal"]))
    elements.append(Spacer(1, 8))

    elements.append(
        Paragraph(
            "Gesamtbewertung der externen Angriffsfläche",
            styles["heading2"],
        )
    )
    elements.append(Spacer(1, 4))
    elements.append(
        Paragraph(
            "Bewertung basiert auf externen, passiven OSINT-Daten; interne Kontrollen sind nicht beurteilbar.",
            styles["normal"],
        )
    )
    elements.append(Spacer(1, 8))

    elements.append(
        Paragraph(
            "Kurzempfehlung: Auftrag zur Härtung der externen Zugänge erteilen und Zielwert Exposure-Level ≤2/5 festlegen.",
            styles["normal"],
        )
    )
    elements.append(Spacer(1, 6))

    elements.append(
        Paragraph(
            "Entscheidungsvorlage: Priorisierung und Ressourcen für die Reduktion der externen Angriffsfläche freigeben.",
            styles["normal"],
        )
    )
    elements.append(Spacer(1, 8))

    # Seite 1 bewusst fokussiert; Rest auf Folgeseiten
    elements.append(PageBreak())

    # ──────────────────────────────────────────────────────────────────────────
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
    intro_text = "Auf Basis passiver OSINT-Daten wurden öffentlich erreichbare Dienste identifiziert."
    elements.append(Paragraph(intro_text, styles["normal"]))
    elements.append(Spacer(1, 4))

    elements.append(
        Paragraph(
            "Einordnung: Externe Sicht; interne Sicherheitsmaßnahmen sind nicht beurteilbar.",
            styles["normal"],
        )
    )
    elements.append(Spacer(1, 4))

    # 4b. Zweiter Absatz: CVE- und Risiko-Situation
    if cve_count == 0:
        cve_text = "Keine kritisch ausnutzbaren, bekannten Schwachstellen festgestellt. Details im technischen Anhang."
    else:
        cve_text = "Bekannte Schwachstellen sind im technischen Anhang dokumentiert."
    elements.append(Paragraph(cve_text, styles["normal"]))
    elements.append(Spacer(1, 4))

    # 4c. Dritter Absatz: Risiko-Einschätzung und Handlungsempfehlung
    if risk_level == "critical":
        risk_text = "Kritische Sicherheitsrisiken erkennbar; Ursachen liegen in extern erreichbaren Diensten."
    elif risk_level == "high":
        risk_text = "Erhöhte Sicherheitsrisiken erkennbar; Ursachen liegen in extern erreichbaren Diensten."
    elif risk_level == "medium":
        risk_text = "Moderate Risiken erkennbar; Ursache ist die externe Erreichbarkeit einzelner Dienste."
    else:  # low
        if critical_cves_count > 0:
            risk_text = "Moderate Risiken erkennbar; Ursache sind OSINT-Hinweise ohne bestätigte Ausnutzung."
        else:
            risk_text = "Keine kritischen Risiken erkennbar; OSINT-Hinweise zeigen keine aktive Ausnutzung."

    elements.append(Paragraph(risk_text, styles["normal"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Details zu Diensten und Befunden sind im Technischen Anhang dokumentiert.", styles["normal"]))
    elements.append(Spacer(1, 12))

    # CVE overview removed from Management section per user request.

    elements.append(Spacer(1, 15))





# ──────────────────────────────────────────────────────────────────────────────
# ENDE DER DATEI
# ──────────────────────────────────────────────────────────────────────────────
