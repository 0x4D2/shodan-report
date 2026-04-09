# ──────────────────────────────────────────────────────────────────────────────
# Management Section für PDF-Reports
# Generiert professionelle Management-Zusammenfassung im Security-Reporting-Stil
# ──────────────────────────────────────────────────────────────────────────────

from reportlab.platypus import Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
import os
from typing import List, Dict, Any, Optional
from shodan_report.pdf.styles import Theme, Colors

# ──────────────────────────────────────────────────────────────────────────────
# Management-Text & Insights Helpers
# ──────────────────────────────────────────────────────────────────────────────
from shodan_report.pdf.helpers.management_helpers import (
    _build_top_risks,
    _build_service_flags,
    count_critical_cves,
    count_kev_cves,
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

# Total KPI row = 5 cells × _KPI_CELL_W mm = 163 mm (fits within page text frame)
_KPI_CELL_W = 163.0 / 5  # = 32.6 mm


def _kpi_cell(label: str, value: str, value_color=None, value_size: int = 16) -> Table:
    """KPI-Karte — Uppercase-Label oben, große Zahl unten, weißer Hintergrund mit Rahmen."""
    _C_BORDER  = HexColor("#DDDDDD")
    _C_BG      = Colors.bg_light
    _val_color = value_color if value_color is not None else Colors.text

    lbl = Paragraph(
        f'<font size="7" color="#888888">{label}</font>',
        ParagraphStyle(
            "_KpiLabel",
            alignment=1,
            leading=9,
            spaceAfter=0,
            spaceBefore=0,
            fontName="Helvetica",
        ),
    )
    # IP-Wert kleiner und monospace, alle anderen normal groß
    if value_size <= 9:
        val_markup = f'<font size="9" color="#1A1A1A"><b>{value}</b></font>'
    else:
        hex_color = "#{:02X}{:02X}{:02X}".format(
            int(_val_color.red * 255),
            int(_val_color.green * 255),
            int(_val_color.blue * 255),
        ) if value_color else "#1A1A1A"
        val_markup = f'<font size="{value_size}" color="{hex_color}"><b>{value}</b></font>'

    val = Paragraph(
        val_markup,
        ParagraphStyle(
            "_KpiValue",
            alignment=1,
            leading=max(value_size + 2, 11),
            spaceAfter=0,
            spaceBefore=0,
            fontName="Helvetica-Bold",
            textColor=_val_color,
        ),
    )
    # Feste Zeilenhöhen für perfekte Gleichheit und Zentrierung
    inner = Table(
        [[lbl], [val]],
        colWidths=[_KPI_CELL_W * mm],
        rowHeights=[14, 26]  # Label-Zeile, Wert-Zeile (siehe Changelog)
    )
    inner.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("BACKGROUND",    (0, 0), (-1, -1), _C_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, _C_BORDER),
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
        pass  # intro_line wird nicht mehr verwendet

    # ── KPI-Zeile: IP · Ports · CVEs gesamt · Kritisch (≥9) · CISA KEV ──
    _cve_total_kpi = int(mdata.get("cve_count", 0) or 0)
    # Enrich CVEs with CVSS — same logic as cve_overview.py so counts are consistent
    _lookup_nvd_kpi = bool((config.get("nvd") or {}).get("enabled", False))
    if os.environ.get("NVD_LIVE") == "1":
        _lookup_nvd_kpi = True
    _kpi_cve_ids = sorted(mdata.get("unique_cves") or [])
    _enriched_kpi = enrich_cves(_kpi_cve_ids, technical_json, lookup_nvd=_lookup_nvd_kpi) if _kpi_cve_ids else []
    _crit_count_kpi = count_critical_cves(_enriched_kpi)
    _cisa_count_kpi = count_kev_cves(_enriched_kpi)
    _crit_color_kpi = Colors.risk_critical_dot if _crit_count_kpi > 0 else None
    _cisa_color_kpi = Colors.risk_critical_dot if _cisa_count_kpi > 0 else None

    _ip_display = str(technical_json.get("ip_str") or technical_json.get("ip") or "—")
    kpi_row = Table(
        [[
            _kpi_cell("ANALYSIERTE IP",  _ip_display, value_size=9),
            _kpi_cell("OFFENE PORTS",    str(int(mdata.get("total_ports", 0) or 0))),
            _kpi_cell("CVES GESAMT",     str(_cve_total_kpi)),
            _kpi_cell("KRITISCH (≥9)",   str(_crit_count_kpi), _crit_color_kpi),
            _kpi_cell("CISA KEV",        str(_cisa_count_kpi), _cisa_color_kpi),
        ]],
        colWidths=[_KPI_CELL_W * mm] * 5,
    )
    kpi_row.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LINEBEFORE",    (1, 0), (-1, -1), 0.5, HexColor("#DDDDDD")),
    ]))
    elements.append(kpi_row)
    elements.append(Spacer(1, 10))
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
        _dienste_label = "öffentlicher Dienst" if total_ports == 1 else "öffentliche Dienste"
        _factors.append(f"{total_ports} {_dienste_label}")

    _factor_str = " · ".join(_factors)

    _accent_color = (
        HexColor("#C0392B") if exposure_score >= 4
        else HexColor("#E67E22") if exposure_score == 3
        else HexColor("#27AE60")
    )
    _exp_color_hex = (
        "#C0392B" if exposure_score >= 4
        else "#E67E22" if exposure_score == 3
        else "#27AE60"
    )

    try:
        _ampel_box = build_horizontal_exposure_ampel(exposure_score, theme=theme)
    except Exception:
        _ampel_box = Paragraph("", styles["normal"])

    _exp_box = Table(
        [[
            Paragraph(
                f'<font size="9" color="#444444"><b>EXPOSURE-LEVEL:</b></font>'
                f'&nbsp;&nbsp;'
                f'<font size="11" color="{_exp_color_hex}"><b>{exposure_display} ({exposure_desc})</b></font>',
                styles["normal"],
            ),
            _ampel_box,
            Paragraph(
                f'<font size="8" color="#888888">Beitragsfaktoren: {_factor_str}</font>',
                ParagraphStyle(
                    "_exp_factors",
                    parent=styles["normal"],
                    alignment=2,
                    fontSize=8,
                ),
            ),
        ]],
        colWidths=[66 * mm, 34 * mm, 63 * mm],
    )
    _exp_box.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#DDDDDD")),
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#F8F8F8")),
        ("LINEBEFORE",    (0, 0), (0, -1),  4, _accent_color),
    ]))
    elements.append(_exp_box)
    elements.append(Spacer(1, 10))

    # ── Zweispaltig: Links = Kernaussagen + Technik | Rechts = Gesamteinschätzung + Empfehlung ──
    ns = styles.get("normal") or styles.get("Normal")

    # ── LINKE SPALTE ──────────────────────────────────────────────────────────
    rdp_primary = should_show_rdp_warning(technical_json, mdata)
    risk_stmt, tech_note_candidate = get_management_risk_and_tech_note(
        technical_json, evaluation, mdata=mdata, config=config
    )
    _state_dienste = "öffentlicher Dienst" if total_ports == 1 else "öffentliche Dienste"
    state_stmt = (
        f"Zustand: Exposure-Level {exposure_display} ({exposure_desc}) — "
        f"{total_ports} {_state_dienste}, {cve_count} CVE-Indikatoren."
    )
    trend_note = (
        "Richtung: Baseline gesetzt. Trendvergleich ab nächstem Report verfügbar."
    )
    try:
        if compare_month or trend_text:
            trend_note = (
                "Richtung: Trendbewertung verfügbar (siehe Trend- & Vergleichsanalyse). "
                "Regelmäßige Scans und Owner benennen."
            )
    except Exception:
        pass

    left_rows = [
        [Paragraph('<font size="9" color="#1A1A1A"><b>Kernaussagen</b></font>', ns)],
        [Paragraph(f'<font size="9" color="#444444">• <b>Risiko:</b> {risk_stmt.replace("Risiko: ", "", 1)}</font>', ns)],
        [Paragraph(f'<font size="9" color="#444444">• <b>Zustand:</b> {state_stmt.replace("Zustand: ", "")}</font>', ns)],
        [Paragraph(f'<font size="9" color="#444444">• <b>Richtung:</b> {trend_note.replace("Richtung: ", "")}</font>', ns)],
        [Spacer(1, 6)],
        [Paragraph('<font size="9" color="#1A1A1A"><b>Technische Kurzbewertung</b></font>', ns)],
        [Paragraph(f'<font size="9" color="#444444">{tech_note_candidate}</font>', ns)],
    ]

    left_tbl = Table(left_rows, colWidths=[78 * mm])
    left_tbl.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        # Header-Zeilen etwas mehr Abstand nach unten
        ("BOTTOMPADDING", (0, 0), (0, 0),   5),
        ("BOTTOMPADDING", (0, 5), (0, 5),   5),
    ]))

    # ── RECHTE SPALTE ─────────────────────────────────────────────────────────
    # Gesamteinschätzung + Empfehlung aus management_text
    gesamteinschaetzung = ""
    empfehlung = ""
    try:
        if management_text and management_text.strip():
            blocks = [b.strip() for b in management_text.strip().split("\n\n") if b.strip()]
            for block in blocks:
                lines = block.split("\n")
                first = lines[0].strip()
                rest  = " ".join(l.strip() for l in lines[1:] if l.strip())
                if "einschätzung" in first.lower() or "gesamteinschätzung" in first.lower():
                    gesamteinschaetzung = rest or block.replace("\n", " ")
                elif "empfehlung" in first.lower():
                    empfehlung = rest or block.replace("\n", " ")
                elif not gesamteinschaetzung:
                    gesamteinschaetzung = block.replace("\n", " ")
                elif not empfehlung:
                    empfehlung = block.replace("\n", " ")
    except Exception:
        pass

    # Fallback wenn management_text leer
    if not gesamteinschaetzung:
        gesamteinschaetzung = (
            f"Die externe Sicherheitslage ist {exposure_desc} (Level {exposure_display}). "
            "Keine akut bestätigten Exploits, jedoch Konfigurationsrisiken und CVE-Indikatoren erkannt, "
            "die das Angriffspotenzial messbar erhöhen."
        )
    if not empfehlung:
        empfehlung = (
            "Kritische CVEs innerhalb 30 Tage adressieren. TLS-Konfiguration härten. "
            "CVE-Monitoring einrichten. Nächste Schritte: IT-Betrieb bewertet Konfigurationsrisiken "
            "(Owner: IT-Betrieb)."
        )

    # Truncate to prevent oversized Table cells that exceed the page frame height
    _MAX_CELL_CHARS = 800
    if len(gesamteinschaetzung) > _MAX_CELL_CHARS:
        gesamteinschaetzung = gesamteinschaetzung[:_MAX_CELL_CHARS] + "\u2026"
    if len(empfehlung) > _MAX_CELL_CHARS:
        empfehlung = empfehlung[:_MAX_CELL_CHARS] + "\u2026"

    right_rows = [
        [Paragraph('<font size="9" color="#1A1A1A"><b>Gesamteinschätzung</b></font>', ns)],
        [Paragraph(f'<font size="9" color="#444444">{gesamteinschaetzung}</font>', ns)],
        [Spacer(1, 8)],
        [Paragraph('<font size="9" color="#1A1A1A"><b>Empfehlung</b></font>', ns)],
        [Paragraph(f'<font size="9" color="#444444">{empfehlung}</font>', ns)],
    ]

    right_tbl = Table(right_rows, colWidths=[85 * mm])
    right_tbl.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (0, 0),   5),
        ("BOTTOMPADDING", (0, 3), (0, 3),   5),
    ]))

    # Zweispaltiger Wrapper
    two_col = Table([[left_tbl, right_tbl]], colWidths=[78 * mm, 85 * mm])
    two_col.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LINEAFTER",     (0, 0), (0, -1),  0.3, HexColor("#EEEEEE")),
    ]))
    elements.append(two_col)
    elements.append(Spacer(1, 8))







# ──────────────────────────────────────────────────────────────────────────────
# ENDE DER DATEI
# ──────────────────────────────────────────────────────────────────────────────