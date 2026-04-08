"""
Fazit & Empfohlene nächste Schritte — Seite 7.
Design: Einleitungstext in grauer Box, dann strukturierte Zeitplan-Tabelle.
"""

from typing import List, Dict, Optional, Any
from reportlab.platypus import Spacer, Paragraph, Table, TableStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white


# ── Farben ────────────────────────────────────────────────────────────────────
C_BORDER    = HexColor("#DDDDDD")
C_INTRO_BG  = HexColor("#F8F8F8")
C_LABEL_TX  = HexColor("#888888")
C_BODY_TX   = HexColor("#333333")


def create_conclusion_section(
    elements: List,
    styles: Dict,
    customer_name: str = "",
    business_risk: str = "MEDIUM",
    context: object = None,
) -> None:
    """
    Fazit & Empfohlene nächste Schritte.
    Liest Exposure-Level, Schritte und Zertifikats-Infos aus context.
    """
    ns = styles.get("normal") or styles.get("Normal")

    elements.append(Spacer(1, 12))
    heading_style = styles.get("heading1") or styles.get("heading2") or ns
    elements.append(Paragraph(
        "<b>7. Fazit &amp; Empfohlene nächste Schritte</b>", heading_style
    ))
    elements.append(Spacer(1, 10))

    # ── Daten aus context ─────────────────────────────────────────────────────
    risk_level     = _extract_risk_level(business_risk)
    exposure_score = None
    next_steps     = []
    technical_json = {}
    evaluation     = {}

    if context is not None:
        try:
            from .data.management_data import prepare_management_data, compute_boosted_exposure_score
            technical_json = getattr(context, "technical_json", {}) or {}
            evaluation     = getattr(context, "evaluation",     {}) or {}
            mdata = prepare_management_data(technical_json, evaluation)
            if mdata.get("risk_level"):
                risk_level = mdata["risk_level"]
            base = mdata.get("exposure_score", 1)
            exposure_score = compute_boosted_exposure_score(
                base, technical_json, mdata.get("cve_count", 0)
            )
        except Exception:
            pass
        next_steps = getattr(context, "next_steps", []) or []

    # ── Einleitungstext ───────────────────────────────────────────────────────
    intro = _build_intro_text(risk_level, exposure_score, customer_name)
    intro_tbl = Table(
        [[Paragraph(f'<font size="9" color="#333333">{intro}</font>', ns)]],
        colWidths=[175 * mm],
    )
    intro_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_INTRO_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(intro_tbl)
    elements.append(Spacer(1, 14))

    # ── Subheader ─────────────────────────────────────────────────────────────
    elements.append(Paragraph(
        '<font size="10" color="#1A1A1A"><b>Empfohlene nächste Schritte</b></font>', ns
    ))
    elements.append(Spacer(1, 8))

    # ── Zeitplan-Tabelle ──────────────────────────────────────────────────────
    steps = _build_steps(risk_level, technical_json, evaluation, next_steps, exposure_score)
    _render_steps_table(elements, styles, steps)


# ─────────────────────────────────────────────────────────────────────────────
# EINLEITUNGSTEXT
# ─────────────────────────────────────────────────────────────────────────────

def _build_intro_text(
    risk_level: str, exposure_score: Optional[int], customer_name: str
) -> str:
    level_str = f"erhöht (Exposure-Level {exposure_score}/5)" if exposure_score else "erhöht"
    rl = risk_level.upper()

    if rl in ("HIGH", "CRITICAL"):
        return (
            f"Die externe Angriffsfläche ist <b>kritisch (Exposure-Level {exposure_score or '?'}/5)</b>. "
            "Akut ausnutzbare Schwachstellen identifiziert. Sofortiger Handlungsbedarf — "
            "Priorisierung der Priorität-1-Maßnahmen innerhalb von 24–72 Stunden empfohlen."
        )
    elif rl == "MEDIUM":
        return (
            f"Die externe Angriffsfläche ist <b>{level_str}</b>. "
            "Konkrete Handlungsfelder sind vorhanden. Keine akut bestätigten Exploits, "
            "jedoch Konfigurationsrisiken und CVE-Indikatoren, die ohne Gegenmaßnahmen "
            "das Kompromittierungsrisiko bei gezielten Angriffen erhöhen."
        )
    else:
        score_str = f"niedrig (Exposure-Level {exposure_score}/5)" if exposure_score else "niedrig"
        return (
            f"Die externe Angriffsfläche ist <b>{score_str}</b>. "
            "Kein akuter Handlungsbedarf — kontinuierliche Überwachung empfohlen, "
            "um Veränderungen der Angriffsfläche frühzeitig zu erkennen."
        )


# ─────────────────────────────────────────────────────────────────────────────
# SCHRITTE ABLEITEN
# ─────────────────────────────────────────────────────────────────────────────

def _build_steps(
    risk_level: str,
    technical_json: Dict,
    evaluation: Dict,
    extra_steps: List,
    exposure_score: Optional[int] = None,
) -> List[Dict]:
    """
    Gibt Liste von Schritt-Dicts zurück:
    { "label": str, "title": str, "body": str }
    """
    steps = []
    rl = risk_level.upper()

    # ── Kurzfristig ───────────────────────────────────────────────────────────
    short_parts = []

    # CVEs
    try:
        cves = (
            technical_json.get("vulnerabilities")
            or technical_json.get("cve_enriched")
            or []
        )
        crit_cves = [
            c for c in cves
            if isinstance(c, dict) and float(c.get("cvss") or 0) >= 9.0
        ]
        if crit_cves:
            ids = ", ".join(c.get("id") or c.get("cve", "") for c in crit_cves[:2])
            cvss = crit_cves[0].get("cvss", "")
            short_parts.append(
                f"<b>Kritische CVEs patchen</b> — OpenSSH-Komponenten aktualisieren "
                f"({ids}, CVSS {cvss})."
            )
    except Exception:
        pass

    # Datenbank / FTP offen
    try:
        services = technical_json.get("services") or technical_json.get("open_ports") or []
        db_ports = [s.get("port") for s in services if isinstance(s, dict)
                    and s.get("port") in (3306, 5432, 1433, 27017, 21)]
        if db_ports:
            db_str = " und ".join(
                f"{'MySQL/MariaDB' if p == 3306 else 'FTP' if p == 21 else str(p)} (Port {p})"
                for p in db_ports[:2]
            )
            short_parts.append(
                f"{db_str} über Firewall-Regeln vom öffentlichen Zugriff trennen."
            )
        # cPanel
        cpanel = [s.get("port") for s in services if isinstance(s, dict)
                  and s.get("port") in (2082, 2083, 2086, 2087)]
        if cpanel:
            short_parts.append("cPanel-Zugriff per IP-Whitelist absichern.")
    except Exception:
        pass

    if short_parts:
        steps.append({
            "label": "KURZFRISTIG (0–30 TAGE)",
            "body":  " ".join(short_parts),
        })

    # ── Mittelfristig ─────────────────────────────────────────────────────────
    mid_parts = []
    try:
        services = technical_json.get("services") or technical_json.get("open_ports") or []
        has_ssh = any(isinstance(s, dict) and s.get("port") == 22 for s in services)
        if has_ssh:
            mid_parts.append(
                "<b>Zugriffshärtung</b> — SSH auf Key-Only-Authentifizierung umstellen, "
                "Fail2ban aktivieren, VPN/Jumphost einrichten."
            )
        # Selbstsigniertes Zertifikat
        has_selfsigned = any(
            isinstance(s, dict) and (s.get("tls") or {}).get("cert_self_signed")
            for s in services
        )
        if has_selfsigned:
            mid_parts.append(
                "Selbstsigniertes Zertifikat auf Port 443 durch CA-signiertes Zertifikat ersetzen."
            )
        mid_parts.append("EOL-Ablaufplan erstellen.")
    except Exception:
        mid_parts.append("<b>Zugriffshärtung</b> — SSH, VPN/Jumphost, MFA aktivieren.")

    if mid_parts:
        steps.append({
            "label": "MITTELFRISTIG (30–90 TAGE)",
            "body":  " ".join(mid_parts),
        })

    # ── Ablaufende Zertifikate ────────────────────────────────────────────────
    try:
        services = technical_json.get("services") or technical_json.get("open_ports") or []
        expiring = []
        for s in services:
            if not isinstance(s, dict):
                continue
            tls  = s.get("tls") or {}
            days = tls.get("cert_expires_in_days")
            port = s.get("port")
            if isinstance(days, int) and 0 <= days <= 30:
                expiring.append((port, days, tls.get("cert_issuer", "")))
        if expiring:
            primary = expiring[0]
            affected_ports = [str(e[0]) for e in expiring[1:6]]
            affected_str = ""
            if affected_ports:
                affected_str = f" Betroffen ebenfalls: Port {', '.join(affected_ports)}."
            steps.append({
                "label": "ABLAUFENDES ZERTIFIKAT",
                "body":  (
                    f"<b>{'FTP' if primary[0]==21 else f'Port {primary[0]}'}-Zertifikat "
                    f"(Port {primary[0]}) läuft in {primary[1]} Tagen ab</b> — "
                    f"sofortige Erneuerung empfohlen. "
                    f"Aussteller: {primary[2] or 'unbekannt'}.{affected_str}"
                ),
            })
    except Exception:
        pass

    # ── Laufend ───────────────────────────────────────────────────────────────
    steps.append({
        "label": "LAUFEND",
        "body":  (
            "<b>Monatliche Wiederholung</b> der Analyse zur Trendbeobachtung. "
            "CVE-Monitoring einrichten. Owner benennen (IT-Betrieb). "
            + (
                f"Ziel: Exposure-Level auf {max(1, exposure_score - 1)}/5 senken."
                if exposure_score and exposure_score > 1
                else "Ziel: Exposure-Level auf 1/5 halten."
            )
        ),
    })

    return steps


# ─────────────────────────────────────────────────────────────────────────────
# SCHRITTE RENDERN
# ─────────────────────────────────────────────────────────────────────────────

def _render_steps_table(elements: List, styles: Dict, steps: List[Dict]) -> None:
    """
    Zweispaltige Tabelle: Label (grau, uppercase, klein) | Text (normal).
    Kein Rahmen, nur horizontale Trennlinien.
    """
    ns = styles.get("normal") or styles.get("Normal")

    rows = []
    for step in steps:
        label_cell = Paragraph(
            f'<font size="8" color="#888888"><b>{step["label"]}</b></font>', ns
        )
        body_cell = Paragraph(
            f'<font size="9" color="#333333">{step["body"]}</font>', ns
        )
        rows.append([label_cell, body_cell])

    tbl = Table(rows, colWidths=[42 * mm, 133 * mm])
    tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (0, -1),  10),
        ("RIGHTPADDING",  (1, 0), (1, -1),  0),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.3, HexColor("#EEEEEE")),
    ]))
    elements.append(tbl)


# ─────────────────────────────────────────────────────────────────────────────
# HILFSFUNKTIONEN
# ─────────────────────────────────────────────────────────────────────────────

def _extract_risk_level(business_risk) -> str:
    if isinstance(business_risk, dict):
        return str(business_risk.get("level", "MEDIUM"))
    elif isinstance(business_risk, str):
        return business_risk
    return str(business_risk)