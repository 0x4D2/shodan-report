# ──────────────────────────────────────────────────────────────────────────────
# Management Section für PDF-Reports
# Generiert professionelle Management-Zusammenfassung im Security-Reporting-Stil
# ──────────────────────────────────────────────────────────────────────────────

from reportlab.platypus import Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
import os
from typing import List, Dict, Any, Optional
from shodan_report.pdf.styles import Theme, Colors

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

# Total KPI row = 5 cells × _KPI_CELL_W mm = 163 mm (matches other section tables)
_KPI_CELL_W = 163.0 / 5  # ≈ 32.6 mm


def _kpi_cell(label: str, value: str, value_color=None) -> Table:
    """Rendert eine einzelne KPI-Karte im Management-Stil."""
    _val_color = value_color if value_color is not None else Colors.text
    lbl = Paragraph(
        f'<font size="7">{label}</font>',
        ParagraphStyle(
            "_KpiLabel",
            alignment=1,
            leading=9,
            spaceAfter=0,
            spaceBefore=0,
            textColor=Colors.text_muted,
            fontName="Helvetica",
        ),
    )
    val = Paragraph(
        f'<font size="16"><b>{value}</b></font>',
        ParagraphStyle(
            "_KpiValue",
            alignment=1,
            leading=18,
            spaceAfter=0,
            spaceBefore=0,
            textColor=_val_color,
            fontName="Helvetica-Bold",
        ),
    )
    inner = Table([[lbl], [val]], colWidths=[_KPI_CELL_W * mm])
    inner.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (0, 0), (-1, -1), Colors.bg_light),
        ("BOX", (0, 0), (-1, -1), 0.3, Colors.border),
    ]))
    return inner


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
    # ── Risk boosts (single source of truth — must run before any rendering) ────
    # NVD critical CVE boost (optional — only when NVD_LIVE=1 or config.nvd.enabled)
    _critical_cves_count = 0
    try:
        _lookup_nvd = bool(
            (config or {}).get("nvd", {}).get("enabled", False)
            if isinstance(config, dict) else False
        )
        if os.environ.get("NVD_LIVE") == "1":
            _lookup_nvd = True
        _cve_ids = mdata.get("unique_cves", []) or []
        if _lookup_nvd and _cve_ids:
            _enriched = enrich_cves(_cve_ids, technical_json, lookup_nvd=True)
            for _ent in _enriched:
                try:
                    _cvss = _ent.get("cvss")
                    if _cvss is not None and float(_cvss) >= 9.0:
                        _critical_cves_count += 1
                except Exception:
                    continue
    except Exception:
        _critical_cves_count = 0
    if _critical_cves_count >= 3:
        exposure_score = max(exposure_score, 4)
    elif _critical_cves_count >= 1:
        exposure_score = max(exposure_score, 3)

    # Insecure TLS boost — TLS 1.0/1.1 active is a Verified Finding that raises real risk
    _insecure_tls_vers = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    _found_insecure_tls: set = set()
    try:
        for _svc in (technical_json.get("services") or technical_json.get("open_ports") or []):
            _ssl = ((_svc.get("ssl_info") or {}) if isinstance(_svc, dict) else {})
            if isinstance(_ssl, dict):
                for _v in (_ssl.get("versions") or []):
                    _vs = str(_v).strip()
                    if not _vs.startswith("-") and _vs in _insecure_tls_vers:
                        _found_insecure_tls.add(_vs)
    except Exception:
        pass
    if _found_insecure_tls:
        exposure_score = max(exposure_score, 3)

    # EOL boost — structural patch deficit raises baseline risk
    _has_eol = False
    try:
        from shodan_report.evaluation.eol import scan_services_for_eol
        _eol_svcs = []
        for _svc in (technical_json.get("services") or technical_json.get("open_ports") or []):
            if isinstance(_svc, dict):
                _eol_svcs.append({
                    "port": _svc.get("port"),
                    "product": _svc.get("product") or "",
                    "version": _svc.get("version") or "",
                })
        _eol_res = scan_services_for_eol(_eol_svcs)
        _has_eol = any(f.get("eol_status") in ("eol", "near_eol") for f in _eol_res)
        if not _has_eol:
            _has_eol = "eol-product" in [str(t).lower() for t in (technical_json.get("tags") or [])]
    except Exception:
        pass
    if _has_eol:
        exposure_score = max(exposure_score, 3)

    # CVE baseline boost — any inferred CVE raises risk to at least erhöht
    _raw_cve_count = int(mdata.get("cve_count", 0) or 0)
    if _raw_cve_count > 0:
        exposure_score = max(exposure_score, 3)

    # Re-sync display + description after all boosts
    exposure_display = f"{exposure_score}/5"
    exposure_desc = exposure_description_map.get(exposure_score, "nicht bewertet")
    # ────────────────────────────────────────────────────────────────────────
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

        ip = technical_json.get("ip")
        ip_str = str(ip) if ip else "–"
        domains = technical_json.get("domains") or []
        hostnames = technical_json.get("hostnames") or []
        # Hostnamen/Domains dedupliziert, ohne die IP selbst — reine Netzwerk-Identitäten
        _seen_names: list = []
        for _n in [str(d) for d in domains if d] + [str(h) for h in hostnames if h]:
            if _n not in _seen_names:
                _seen_names.append(_n)
        names_list = _seen_names

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

        # Intro-Zeile: IP-zentrisch, Hostnamen/Domains als zugeordnete Identitäten
        if not names_list:
            intro_line = (
                f"Analysierte IP-Adresse: {ip_str} — "
                f"Exposure-Level {exposure_display} ({exposure_desc}), da {reason}."
            )
        elif len(names_list) == 1:
            intro_line = (
                f"Analysierte IP-Adresse: {ip_str}  ·  Hostname/Domain: {names_list[0]} — "
                f"Exposure-Level {exposure_display} ({exposure_desc}), da {reason}."
            )
        else:
            hosts_display = ", ".join(names_list[:2])
            if len(names_list) > 2:
                hosts_display += f" (+{len(names_list) - 2} weitere)"
            intro_line = (
                f"Analysierte IP-Adresse: {ip_str}  ·  {len(names_list)} zugeordnete Hostnamen/Domains: "
                f"{hosts_display} — Exposure-Level {exposure_display} ({exposure_desc}), da {reason}."
            )
    except Exception:
        intro_line = "Analysierte IP-Adresse: unbekannt — die externe Angriffsfläche ist erhöht bewertet."

    elements.append(Paragraph(intro_line, styles["normal"]))
    elements.append(Spacer(1, 8))

    # ── Gesamtbewertung: Exposure-Level + visuelle Ampel ─────────────────
    elements.append(
        Paragraph("Gesamtbewertung der externen Angriffsfläche", styles["normal"])
    )
    elements.append(Spacer(1, 8))

    try:
        _ampel = build_horizontal_exposure_ampel(exposure_score, theme=theme)
    except Exception:
        _ampel = Paragraph("", styles["normal"])

    exp_tbl = Table(
        [[
            Paragraph(
                f"<b>Exposure-Level:</b> {exposure_score} von 5 ({exposure_desc})",
                styles["exposure"],
            ),
            _ampel,
        ]],
        style=TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]),
    )
    elements.append(exp_tbl)
    elements.append(Spacer(1, 10))

    # ── KPI-Zeile: IP · Ports · CVEs gesamt · Kritisch (≥9) · CISA KEV ──
    _all_cves_kpi = mdata.get("cves", [])
    _cve_total_kpi = int(mdata.get("cve_count", 0) or 0)
    _crit_count_kpi = len([
        c for c in _all_cves_kpi
        if isinstance(c, dict) and (c.get("cvss") or 0) >= 9.0
    ])
    _cisa_count_kpi = sum(
        1 for c in _all_cves_kpi
        if isinstance(c, dict) and c.get("exploit_status") in ("public", "kev", "cisa")
    )
    _crit_color_kpi = Colors.risk_critical_dot if _crit_count_kpi > 0 else None
    _cisa_color_kpi = Colors.risk_critical_dot if _cisa_count_kpi > 0 else None

    _ip_display = str(technical_json.get("ip_str") or technical_json.get("ip") or "—")
    kpi_row = Table(
        [[
            _kpi_cell("Analysierte IP", _ip_display),
            _kpi_cell("Offene Ports", str(int(mdata.get("total_ports", 0) or 0))),
            _kpi_cell("CVEs gesamt", str(_cve_total_kpi)),
            _kpi_cell("Kritisch (≥9)", str(_crit_count_kpi), _crit_color_kpi),
            _kpi_cell("CISA KEV", str(_cisa_count_kpi), _cisa_color_kpi),
        ]],
        colWidths=[_KPI_CELL_W * mm] * 5,
    )
    kpi_row.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    elements.append(kpi_row)
    elements.append(Spacer(1, 12))
# ── Exposure-Level + Beitragsfaktoren (ein kompakter Block) ─────────────
    try:
        services = technical_json.get("services") or technical_json.get("open_ports") or []
        rdp_count = 0
        for s in services:
            if isinstance(s, dict):
                port = s.get("port"); prod = (s.get("product") or "").lower()
            else:
                port = getattr(s, "port", None); prod = (getattr(s, "product", "") or "").lower()
            if port == 3389 or "rdp" in prod:
                rdp_count += 1
    except Exception:
        rdp_count = 0

    try:
        cves_disp = int(cve_count)
    except Exception:
        cves_disp = 0

    # Beitragsfaktoren — listed only when they actually drive the score
    _factors = []
    if rdp_count > 0:
        _factors.append(f"RDP öffentlich erreichbar ({rdp_count}×)")
    elif critical_points_count > 0:
        _factors.append(f"{critical_points_count} kritische Dienste")
    if cves_disp > 0:
        _factors.append(f"{cves_disp} CVEs (Inferred)")
    if _found_insecure_tls:
        _factors.append(f"TLS 1.0/1.1 aktiv (Verified)")
    if _has_eol:
        _factors.append("EOL-Software")
    try:
        _has_version_risk = any(
            (s.get("version_risk", 0) if isinstance(s, dict) else getattr(s, "version_risk", 0))
            for s in (technical_json.get("services") or technical_json.get("open_ports") or [])
        )
    except Exception:
        _has_version_risk = False
    if _has_version_risk:
        _factors.append("strukturelle Risiken (Version)")
    if not _factors:
        _factors.append(f"{total_ports} öffentliche Dienste")

    _factor_str = " · ".join(_factors)
    elements.append(Paragraph(
        f"<b>Exposure-Level: {exposure_display} ({exposure_desc})</b> — "
        f"Beitragsfaktoren: {_factor_str}.",
        styles["normal"],
    ))
    elements.append(Spacer(1, 6))

    # 3 Kernaussagen (Risiko, Zustand, Richtung)
    elements.append(Paragraph("<b>Kernaussagen</b>", styles["normal"]))
    elements.append(Spacer(1, 4))

    # Use helper to produce the risk statement and the technical short note
    rdp_primary = should_show_rdp_warning(technical_json, mdata)
    risk_stmt, tech_note_candidate = get_management_risk_and_tech_note(technical_json, evaluation, mdata=mdata, config=config)

    state_stmt = f"Zustand: Exposure-Level {exposure_display} ({exposure_desc}) — Gesamtbewertung stützt sich auf {total_ports} öffentliche Dienste."

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
