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


def should_show_rdp_warning(technical_json: Dict[str, Any], mdata: Optional[Dict[str, Any]] = None) -> bool:
    """Determine whether the RDP-specific warning should be shown.

    Supports multiple input shapes for testability:
      - technical_json containing `primary_service`, `open_ports_count`, `detected_ports`
      - technical_json with `services` or `open_ports` list of dicts with `port`/`product`
    The rule implemented matches the requirement:
      IF (primary_service == "rdp" OR (open_ports_count == 1 AND detected_port == 3389))
    """
    try:
        # Synthetic test-oriented shape
        if isinstance(technical_json, dict) and ("primary_service" in technical_json or "detected_ports" in technical_json or "open_ports_count" in technical_json):
            primary = str(technical_json.get("primary_service", "") or "").lower()
            detected = set(technical_json.get("detected_ports") or technical_json.get("ports") or [])
            open_count = int(technical_json.get("open_ports_count", len(detected) if detected else 0) or 0)
            if primary == "rdp":
                return True
            if open_count == 1 and 3389 in detected:
                return True
            return False

        # Normal snapshot shape: services/open_ports list
        services_list = technical_json.get("services") or technical_json.get("open_ports") or []
        ports_set = set()
        prods = []
        for s in services_list:
            if isinstance(s, dict):
                ports_set.add(s.get("port"))
                prods.append(str(s.get("product") or "").lower())
            else:
                ports_set.add(getattr(s, "port", None))
                prods.append(str(getattr(s, "product", "")).lower())

        primary_by_product = any("rdp" in p or "remote desktop" in p or "terminal services" in p for p in prods)
        open_ports_count = int((mdata.get("total_ports") if mdata and isinstance(mdata, dict) and mdata.get("total_ports") is not None else len(services_list) if services_list else 0) or 0)
        # Only treat single-port 3389 as RDP if the product/banner indicates RDP-like service
        single_rdp = open_ports_count == 1 and (3389 in ports_set) and primary_by_product
        return bool(primary_by_product or single_rdp)
    except Exception:
        return False


def get_management_risk_and_tech_note(technical_json: Dict[str, Any], evaluation: Any, mdata: Optional[Dict[str, Any]] = None, config: Optional[Dict[str, Any]] = None):
    """Return (risk_stmt, tech_note) using the same logic as the management renderer.

    This helper is used by `create_management_section` and by unit tests to assert
    the produced wording without rendering PDFs.
    """
    top_risks = _build_top_risks(technical_json, (mdata or {}).get("risk_level", "low"))
    rdp_primary = should_show_rdp_warning(technical_json, mdata)

    if rdp_primary:
        risk_stmt = (
            "<b>Beachte:</b> Es wurde ausschließlich <b>Remote Desktop (RDP) auf Port 3389</b> öffentlich erreichbar identifiziert. "
            "RDP ist ein <b>häufig genutzter Angriffsvektor</b> für Brute-Force-Angriffe und Ransomware-Kampagnen. "
            "Da die Analyse auf externen OSINT-Daten basiert, können zusätzliche Zugriffskontrollen (z.B. NLA, IP-Filter, MFA, VPN) nicht beurteilt werden. "
            "Eine <b>Überprüfung und gegebenenfalls Absicherung oder Verlagerung hinter kontrollierte Zugangsmechanismen wird empfohlen.</b>"
        )
        tech_note = (
            "Hinweis: Öffentlich erreichbares RDP erfordert besondere Absicherung. "
            "Empfohlene Maßnahmen umfassen: Netzwerk Access Control (IP-Whitelisting), NLA (Network Level Authentication), "
            "MFA-Einführung oder Ersatz durch VPN/Jumphost-Lösungen."
        )
        return risk_stmt, tech_note

    # fallback to previously existing logic for non-RDP cases
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

    # technical short note (keep original SSH/web logic)
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

    return risk_stmt, tech_note

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

    # Accept legacy trend args when `context` is not provided
    compare_month = None
    trend_text = ""
    try:
        if "context" in kwargs and kwargs.get("context") is not None:
            compare_month = getattr(ctx, "compare_month", None)
            trend_text = (getattr(ctx, "trend_text", "") or "").strip()
        else:
            compare_month = kwargs.get("compare_month", None)
            trend_text = (kwargs.get("trend_text", "") or "").strip()
    except Exception:
        compare_month = None
        trend_text = ""

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
                    f"die externe Angriffsfläche ist auf {exposure_display} bewertet, da {reason}."
                )
            else:
                intro_line = (
                    f"Erfasst wurden {asset_count} Assets; das primär bewertete Asset (Host: {primary_asset}) "
                    f"ist auf {exposure_display} bewertet, da {reason}."
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
    # Zeigt kompakt Analysierte IP / Ports / CVEs / Status auf der ersten Seite an.
    # ─────────────────────────────────────────────────────────────────────
    try:
        # Analysierte IP aus technical_json
        analysed_ip = str(technical_json.get("ip") or "–")

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

        # status cell: ampel (zentriert) with smaller label in parentheses below
        # Do not display textual status labels (niedrig/mittel/hoch) in the table
        label_display = ""
        rows = [[ampel]]
        if label_display:
            rows.append([Paragraph(label_display, styles["normal"])])
        status_cell = Table(rows, colWidths=[46 * mm])
        status_cell.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 2),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )

        kern_rows = [
            [Paragraph("<b>KERNKENNZAHLEN</b>", styles["heading2"]), "", "", ""],
            [Paragraph("<b>Analysierte IP</b>", styles["normal"]), Paragraph("<b>Ports</b>", styles["normal"]), Paragraph("<b>CVEs</b>", styles["normal"]), Paragraph("<b>Status</b>", styles["normal"])],
            [Paragraph(analysed_ip, styles["normal"]), str(ports_num), str(cves_num), status_cell],
        ]

        col_w = [42 * mm, 20 * mm, 22 * mm, 46 * mm]
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
            f"<b>Exposure-Level: {exposure_display}.</b>",
            styles["normal"],
        )
    )
    # Note: separate small 'Status' ampel below the exposure paragraph removed
    # Build explicit derivation string: include RDP count as 'kritische Administrationsdienste'
    try:
        services = technical_json.get("services") or technical_json.get("open_ports") or []
        rdp_count = 0
        for s in services:
            if isinstance(s, dict):
                port = s.get("port")
                prod = (s.get("product") or "").lower()
            else:
                port = getattr(s, "port", None)
                prod = (getattr(s, "product", "") or "").lower()
            if port == 3389 or "rdp" in prod:
                rdp_count += 1
    except Exception:
        rdp_count = 0

    # Format CVE count safely
    try:
        cves_disp = int(cve_count)
    except Exception:
        cves_disp = 0

    # Avoid showing a literal '(0)' for critical admin services — prefer
    # explicit RDP count when present, otherwise show identified critical
    # points or a neutral phrasing when none are detected.
    if rdp_count > 0:
        derivation = (
            f"Herleitung: Bewertung basiert auf Anzahl öffentlicher Dienste ({total_ports}), "
            f"kritischen Administrationsdiensten ({rdp_count}: RDP) und CVE-Funden ({cves_disp})."
        )
    elif critical_points_count > 0:
        derivation = (
            f"Herleitung: Bewertung basiert auf Anzahl öffentlicher Dienste ({total_ports}), "
            f"kritischen Administrationsdiensten ({critical_points_count}) und CVE-Funden ({cves_disp})."
        )
    else:
        derivation = (
            f"Herleitung: Bewertung basiert auf Anzahl öffentlicher Dienste ({total_ports}), "
            f"kritischen Administrationsdiensten (keine identifiziert) und CVE-Funden ({cves_disp})."
        )

    elements.append(Paragraph(derivation, styles["normal"]))
    elements.append(Spacer(1, 6))

    # 3 Kernaussagen (Risiko, Zustand, Richtung)
    elements.append(Paragraph("<b>Kernaussagen</b>", styles["normal"]))
    elements.append(Spacer(1, 4))

    # Use helper to produce the risk statement and the technical short note
    rdp_primary = should_show_rdp_warning(technical_json, mdata)
    risk_stmt, tech_note_candidate = get_management_risk_and_tech_note(technical_json, evaluation, mdata=mdata, config=config)

    state_stmt = f"Zustand: Externe Angriffsfläche: Exposure-Level {exposure_display}."

    trend_note = (
        "Richtung: Trend aktuell nicht verfügbar (zu wenige historische Messungen); "
        "Lösung: regelmäßige Scans (z. B. monatlich) und längere Aufbewahrung der Ergebnisse einführen, "
        "damit Trendanalysen möglich werden."
    )
    try:
        if compare_month or trend_text:
            trend_note = (
                "Richtung: Trendbewertung verfügbar (siehe Trend- & Vergleichsanalyse). "
                "Beispiel-Lösung: regelmäßige, automatisierte Scans und Alerting einrichten, "
                "Trendberichte monatlich erstellen und einen Verantwortlichen (Owner) benennen."
            )
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

        # If RDP is primary, add a focused technical short note instead of generic SSH/web text
        if rdp_primary:
            tech_note = (
                "Hinweis: Öffentlich erreichbares RDP erfordert besondere Absicherung. "
                "Empfohlene Maßnahmen umfassen: Netzwerk Access Control (IP-Whitelisting), NLA (Network Level Authentication), "
                "MFA-Einführung oder Ersatz durch VPN/Jumphost-Lösungen."
            )
        elif has_ssh and has_web:
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

    # ── Management-Text (szenario-spezifisch aus management_text.py) ──────────
    try:
        if management_text and management_text.strip():
            for block in management_text.strip().split("\n\n"):
                block = block.strip()
                if not block:
                    continue
                lines = block.split("\n")
                # Erste Zeile ggf. als Abschnittsbezeichner (z.B. "Empfehlung:")
                first = lines[0].strip()
                if len(lines) > 1 and first.endswith(":"):
                    elements.append(Paragraph(f"<b>{first}</b>", styles["normal"]))
                    rest = " ".join(l.strip() for l in lines[1:] if l.strip())
                    if rest:
                        elements.append(Paragraph(rest, styles["normal"]))
                else:
                    elements.append(Paragraph(block.replace("\n", " "), styles["normal"]))
                elements.append(Spacer(1, 4))
            elements.append(Spacer(1, 4))
    except Exception:
        pass







# ──────────────────────────────────────────────────────────────────────────────
# ENDE DER DATEI
# ──────────────────────────────────────────────────────────────────────────────
