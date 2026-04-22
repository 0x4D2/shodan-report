"""
Attack Scenario Section — "Realistisches Angriffsszenario"

Zeigt eine vierstufige Angriffskette (Reconnaissance → Schwachstellen-Prüfung →
Zugriff → Impact) basierend auf den tatsächlich exponierten Diensten.

Gate: Wenn ausschließlich Webdienste exponiert sind (kein Admin/DB/Mail/FTP)
wird statt der Kette eine Positiv-Box gerendert.
"""

from typing import List, Dict, Any, Optional

from reportlab.lib.colors import HexColor, white
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

from shodan_report.pdf.layout import keep_section
from shodan_report.pdf.helpers.management_helpers import (
    _build_top_risks,
    _extract_services,
    _svc_label,
    _join_labels,
    _ADMIN_PORT_INFO,
    _ADMIN_PRODUCT_KEYWORDS,
    _DB_PORT_INFO,
    _DB_PRODUCT_KEYWORDS,
)


_CONTENT_W = 170 * mm

# ── Farben ────────────────────────────────────────────────────────────────────
_C_BORDER      = HexColor("#DDDDDD")

_C_SEVERITY_CRIT_BG = HexColor("#FDECEA")
_C_SEVERITY_CRIT_BD = HexColor("#C0392B")
_C_SEVERITY_CRIT_TX = HexColor("#C0392B")

_C_SEVERITY_MED_BG  = HexColor("#FEF3E8")
_C_SEVERITY_MED_BD  = HexColor("#E67E22")
_C_SEVERITY_MED_TX  = HexColor("#E67E22")

_C_SEVERITY_LOW_BG  = HexColor("#F4F8F4")
_C_SEVERITY_LOW_BD  = HexColor("#27AE60")
_C_SEVERITY_LOW_TX  = HexColor("#27AE60")

_C_POSITIVE_BG      = HexColor("#F0FDF4")
_C_POSITIVE_BD      = HexColor("#27AE60")
_C_POSITIVE_ACCENT  = HexColor("#166534")

_C_NUM_BG           = HexColor("#FEF2F2")
_C_NUM_TX           = HexColor("#C0392B")
_C_CHAIN_BORDER     = HexColor("#E8E8E8")
_C_HINT_BG          = HexColor("#EFF6FF")
_C_HINT_BD          = HexColor("#BFDBFE")
_C_HINT_TX          = HexColor("#1E40AF")


# ── Legacy-Hilfsfunktionen (für Abwärtskompatibilität der Tests) ──────────────

def _severity_colors(severity: str):
    s = severity.lower()
    if any(k in s for k in ("hoch", "kritisch", "high", "critical")):
        return _C_SEVERITY_CRIT_BG, _C_SEVERITY_CRIT_BD, _C_SEVERITY_CRIT_TX
    if any(k in s for k in ("mittel", "medium")):
        return _C_SEVERITY_MED_BG, _C_SEVERITY_MED_BD, _C_SEVERITY_MED_TX
    return _C_SEVERITY_LOW_BG, _C_SEVERITY_LOW_BD, _C_SEVERITY_LOW_TX


def _severity_badge(severity: str, styles: Dict) -> Table:
    bg, bd, tx = _severity_colors(severity)
    tx_hex = "#{:02X}{:02X}{:02X}".format(
        int(tx.red * 255), int(tx.green * 255), int(tx.blue * 255)
    )
    badge = Table(
        [[Paragraph(f'<font size="8" color="{tx_hex}"><b>{severity.upper()}</b></font>',
                    styles.get("body_small", styles.get("Normal")))]],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), bg),
        ("BOX",           (0, 0), (0, 0), 0.8, bd),
        ("ALIGN",         (0, 0), (0, 0), "CENTER"),
        ("VALIGN",        (0, 0), (0, 0), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (0, 0), 5),
        ("RIGHTPADDING",  (0, 0), (0, 0), 5),
        ("TOPPADDING",    (0, 0), (0, 0), 1),
        ("BOTTOMPADDING", (0, 0), (0, 0), 1),
    ]))
    return badge


def _risk_card(risk: Dict, styles: Dict, idx: int) -> Table:
    """Legacy-Risiko-Karte — bleibt für bestehende Tests erhalten."""
    s      = styles.get("Normal")
    s_small = styles.get("body_small", s)
    bg, bd, _ = _severity_colors(risk.get("severity", "niedrig"))

    title     = risk.get("title", "—")
    severity  = risk.get("severity", "—")
    cause     = risk.get("cause", "—")
    scenario  = risk.get("scenario", "—")
    impact    = risk.get("impact", "—")
    rec       = risk.get("recommendation", "—")

    header_row = Table(
        [[
            Paragraph(f'<font size="10" color="#1A1A1A"><b>{idx}. {title}</b></font>', s),
            _severity_badge(severity, styles),
        ]],
        colWidths=[130 * mm, 30 * mm],
    )
    header_row.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("ALIGN",         (1, 0), (1, 0), "RIGHT"),
    ]))

    detail_rows = [
        [
            Paragraph('<font size="8" color="#888888"><b>URSACHE</b></font>', s_small),
            Paragraph(f'<font size="9" color="#444444">{cause}</font>', s_small),
        ],
        [
            Paragraph('<font size="8" color="#888888"><b>SZENARIO</b></font>', s_small),
            Paragraph(f'<font size="9" color="#444444">{scenario}</font>', s_small),
        ],
        [
            Paragraph('<font size="8" color="#888888"><b>AUSWIRKUNG</b></font>', s_small),
            Paragraph(f'<font size="9" color="#444444">{impact}</font>', s_small),
        ],
        [
            Paragraph('<font size="8" color="#888888"><b>EMPFEHLUNG</b></font>', s_small),
            Paragraph(f'<font size="9" color="#444444">{rec}</font>', s_small),
        ],
    ]
    detail_tbl = Table(detail_rows, colWidths=[30 * mm, 130 * mm])
    detail_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, _C_BORDER),
        ("LINEBELOW",     (0, -1), (-1, -1), 0, _C_BORDER),
    ]))

    card_inner = Table(
        [[header_row], [Spacer(1, 5)], [detail_tbl]],
        colWidths=[_CONTENT_W - 20 * mm],
    )
    card_inner.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))

    card = Table([[card_inner]], colWidths=[_CONTENT_W])
    card.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), white),
        ("BOX",           (0, 0), (-1, -1), 0.5, bd),
        ("LINEBEFORE",    (0, 0), (0, -1), 3, bd),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return card


def _positive_box(styles: Dict) -> Table:
    """Positiv-Box für Targets mit ausschließlich Web-Exposure."""
    s = styles.get("Normal")
    s_small = styles.get("body_small", s)

    box = Table(
        [
            [Paragraph(
                '<font size="10" color="#166534"><b>Keine kritischen Angriffsvektoren identifiziert</b></font>',
                s,
            )],
            [Spacer(1, 4)],
            [Paragraph(
                '<font size="9" color="#166534">'
                'Die externe Angriffsfläche ist gut reduziert. Es wurden ausschließlich '
                'Standard-Webdienste (HTTP/HTTPS) identifiziert — keine exponierten '
                'Administrations-, Datenbank- oder Remote-Zugangsdienste.'
                '</font>',
                s_small,
            )],
            [Spacer(1, 6)],
            [Paragraph(
                '<font size="9" color="#444444">'
                'Empfehlungen zur weiteren Härtung (TLS-Konfiguration, Security-Header, '
                'Banner-Reduktion) finden sich in der Sektion Handlungsempfehlungen.'
                '</font>',
                s_small,
            )],
        ],
        colWidths=[_CONTENT_W - 20 * mm],
    )
    box.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    outer = Table([[box]], colWidths=[_CONTENT_W])
    outer.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _C_POSITIVE_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, _C_POSITIVE_BD),
        ("LINEBEFORE",    (0, 0), (0, -1), 3, _C_POSITIVE_BD),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return outer


# ── Gate-Logik ────────────────────────────────────────────────────────────────

def _is_web_only(technical_json: Dict[str, Any]) -> bool:
    """True wenn ausschließlich Web-Ports exponiert sind (kein Admin, DB, Mail, FTP)."""
    svcs = _extract_services(technical_json)
    for s in svcs:
        port   = s.get("port")
        prod_l = str(s.get("product") or "").lower()
        if port in _ADMIN_PORT_INFO:
            return False
        if any(kw in prod_l for kw in _ADMIN_PRODUCT_KEYWORDS):
            return False
        if port in _DB_PORT_INFO:
            return False
        if any(kw in prod_l for kw in _DB_PRODUCT_KEYWORDS):
            return False
        if port in {25, 110, 143, 587, 993, 995}:
            return False
        if port == 21 or "ftp" in prod_l:
            return False
    return True


# ── Angriffskette ─────────────────────────────────────────────────────────────

_KNOWN_PORT_NAMES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 5601: "Kibana",
    2082: "cPanel HTTP", 2083: "cPanel HTTPS",
    2086: "WHM HTTP", 2087: "WHM HTTPS",
    2095: "Webmail HTTP", 2096: "Webmail HTTPS",
}


def _build_attack_chain(technical_json: Dict[str, Any], context=None) -> List[Dict]:
    """Baut die 4-Schritt-Angriffskette mit datengetriebenen Texten."""
    svcs = _extract_services(technical_json)

    admin_labels: List[str] = []
    db_labels:    List[str] = []
    mail_labels:  List[str] = []
    ftp_labels:   List[str] = []
    all_labels:   List[str] = []
    versioned:    List[str] = []

    for s in svcs:
        port    = s.get("port")
        product = str(s.get("product") or "").strip()
        version = str(s.get("version") or "").strip()
        prod_l  = product.lower()

        fallback = _KNOWN_PORT_NAMES.get(port, f"Port {port}") if port else "unbekannter Dienst"
        label = _svc_label(port, product, version, fallback)
        all_labels.append(label)
        if product and version:
            versioned.append(f"{product} {version}")
        elif product:
            versioned.append(product)

        if port in _ADMIN_PORT_INFO or any(kw in prod_l for kw in _ADMIN_PRODUCT_KEYWORDS):
            admin_labels.append(label)
        elif port in _DB_PORT_INFO or any(kw in prod_l for kw in _DB_PRODUCT_KEYWORDS):
            db_labels.append(label)
        elif port in {25, 110, 143, 587, 993, 995}:
            mail_labels.append(label)
        elif port == 21 or "ftp" in prod_l:
            ftp_labels.append(label)

    # CVEs aus services oder context
    cve_snippets: List[str] = []
    for s in svcs:
        for cve in (s.get("cves") or [])[:2]:
            if not isinstance(cve, dict):
                continue
            cid  = cve.get("id") or cve.get("cve_id", "")
            cvss = cve.get("cvss") or cve.get("cvss_score", "")
            if cid and cvss:
                try:
                    cve_snippets.append(f"{cid} (CVSS {float(cvss):.1f})")
                except (ValueError, TypeError):
                    cve_snippets.append(f"{cid} (CVSS {cvss})")
        if len(cve_snippets) >= 3:
            break

    if not cve_snippets and context is not None:
        ev = getattr(context, "evaluation", {}) or {}
        try:
            ev_cves = ev.get("cves") if isinstance(ev, dict) else []
        except Exception:
            ev_cves = []
        for cve in (ev_cves or [])[:2]:
            if not isinstance(cve, dict):
                continue
            cid  = cve.get("id") or cve.get("cve_id", "")
            cvss = cve.get("cvss") or cve.get("cvss_score", "")
            if cid and cvss:
                try:
                    cve_snippets.append(f"{cid} (CVSS {float(cvss):.1f})")
                except (ValueError, TypeError):
                    cve_snippets.append(f"{cid} (CVSS {cvss})")

    # Step 1: Reconnaissance
    if all_labels:
        svc_list = _join_labels(all_labels)
        step1_body = (
            f"Globale Scanner (Shodan, Censys, Masscan) identifizieren offene Ports — "
            f"darunter <b>{svc_list}</b>."
        )
    else:
        step1_body = (
            "Globale Scanner (Shodan, Censys, Masscan) identifizieren offene Ports "
            "und exponierte Dienste dieser IP."
        )

    steps: List[Dict] = [{
        "num":   "01",
        "title": "Automatisierter Reconnaissance-Scan",
        "body":  step1_body,
        "note":  "Dieser Vorgang läuft 24/7 weltweit. Kein manueller Aufwand für den Angreifer.",
    }]

    # Step 2: Vulnerability Check
    if cve_snippets:
        svc_ref = _join_labels(versioned[:2]) if versioned else "den exponierten Diensten"
        cve_ref = _join_labels(cve_snippets[:2])
        step2_body = (
            f"Bekannte CVEs für <b>{svc_ref}</b> werden automatisch getestet. "
            f"Darunter <b>{cve_ref}</b>."
        )
        step2_note = "Exploit-Frameworks wie Metasploit enthalten fertige Module für diese CVEs."
    else:
        svc_ref = _join_labels(versioned[:2]) if versioned else "der exponierten Dienste"
        step2_body = (
            f"Produkt- und Versionserkennung (<b>{svc_ref}</b>) ermöglicht "
            "automatisiertes Schwachstellen-Scanning."
        )
        step2_note = "Öffentliche Exploit-Datenbanken werden täglich mit neuen Schwachstellen aktualisiert."

    steps.append({
        "num":   "02",
        "title": "Schwachstellen-Prüfung",
        "body":  step2_body,
        "note":  step2_note,
    })

    # Step 3: Access
    access_targets = admin_labels + db_labels + mail_labels + ftp_labels
    if access_targets:
        target_str = _join_labels(access_targets[:3])
        plural = len(access_targets) > 1
        if admin_labels:
            step3_body = (
                f"<b>{target_str}</b> {'sind' if plural else 'ist'} ohne IP-Beschränkung erreichbar. "
                "Credential-Stuffing und Bruteforce-Angriffe werden automatisch durchgeführt."
            )
        elif db_labels:
            step3_body = (
                f"<b>{target_str}</b> {'sind' if plural else 'ist'} direkt aus dem Internet erreichbar. "
                "Automatisierte Scans auf Standardpasswörter und Authentifizierungslücken "
                "laufen kontinuierlich."
            )
        else:
            step3_body = (
                f"<b>{target_str}</b> {'sind' if plural else 'ist'} ohne IP-Beschränkung erreichbar. "
                "Automatisierte Angriffs-Scans laufen rund um die Uhr."
            )
    else:
        step3_body = (
            "Exponierte Dienste ermöglichen automatisiertes Testen auf schwache "
            "Konfigurationen und bekannte Standardpasswörter."
        )

    steps.append({
        "num":   "03",
        "title": "Zugriff über exponierte Dienste",
        "body":  step3_body,
        "note":  None,
    })

    # Step 4: Impact
    if db_labels and admin_labels:
        target_desc = "die Datenbank oder das Admin-Panel"
    elif db_labels:
        target_desc = "die Datenbank"
    elif admin_labels:
        target_desc = "das Admin-Panel"
    else:
        target_desc = "die exponierten Dienste"

    steps.append({
        "num":   "04",
        "title": "Datenexfiltration oder Ransomware",
        "body":  (
            f"Nach erfolgreichem Zugriff auf <b>{target_desc}</b> werden Daten extrahiert "
            "oder Systeme durch <b>Ransomware</b> verschlüsselt."
        ),
        "note":  "Reaktionszeit bis zur Erkennung ohne Monitoring: typischerweise Stunden bis Tage.",
    })

    return steps


def _chain_card(step: Dict, styles: Dict) -> Table:
    """Rendert eine Schritt-Karte der Angriffskette."""
    ns       = styles.get("Normal")
    ns_small = styles.get("body_small", ns)

    num   = step.get("num", "??")
    title = step.get("title", "")
    body  = step.get("body", "")
    note  = step.get("note") or ""

    # Linke Spalte: große rote Nummer
    num_para = Paragraph(
        f'<font size="15" color="#C0392B"><b>{num}</b></font>',
        ParagraphStyle("_num", alignment=1, leading=18, spaceBefore=0, spaceAfter=0),
    )
    num_cell = Table([[num_para]], colWidths=[18 * mm])
    num_cell.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("BACKGROUND",    (0, 0), (-1, -1), _C_NUM_BG),
    ]))

    # Rechte Spalte: Titel + Body + Note
    right_rows: list = [
        [Paragraph(f'<font size="10" color="#1A1A1A"><b>{title}</b></font>', ns)],
        [Paragraph(f'<font size="9" color="#333333">{body}</font>', ns)],
    ]
    if note:
        right_rows.append([Paragraph(
            f'<font size="8" color="#888888">{note}</font>',
            ns_small,
        )])

    content_w = _CONTENT_W - 18 * mm - 20 * mm  # Nummernzelle + Padding
    right_tbl = Table(right_rows, colWidths=[content_w])
    right_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (0, 0),   4),
    ]))

    card = Table(
        [[num_cell, right_tbl]],
        colWidths=[18 * mm, _CONTENT_W - 18 * mm],
    )
    card.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), white),
        ("BOX",           (0, 0), (-1, -1), 0.5, _C_CHAIN_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",    (0, 0), (0, 0),   0),
        ("BOTTOMPADDING", (0, 0), (0, 0),   0),
        ("LEFTPADDING",   (0, 0), (0, 0),   0),
        ("RIGHTPADDING",  (0, 0), (0, 0),   0),
        ("LEFTPADDING",   (1, 0), (1, 0),   10),
        ("RIGHTPADDING",  (1, 0), (1, 0),   10),
        ("TOPPADDING",    (1, 0), (1, 0),   8),
        ("BOTTOMPADDING", (1, 0), (1, 0),   8),
    ]))
    return card


def _hinweis_box(styles: Dict) -> Table:
    """Blauer Hinweis-Kasten am Ende der Angriffskette."""
    ns_small = styles.get("body_small", styles.get("Normal"))

    inner = Table(
        [[Paragraph(
            '<font size="9" color="#1E40AF">'
            '<b>Hinweis:</b> Diese Angriffskette läuft <b>vollautomatisiert</b>. '
            'Angriffsversuche auf exponierte Dienste beginnen typischerweise '
            'innerhalb von <b>Minuten bis Stunden</b> nach erstmaliger Erreichbarkeit — '
            'unabhängig von Unternehmensgröße oder Branche.'
            '</font>',
            ns_small,
        )]],
        colWidths=[_CONTENT_W - 24 * mm],
    )
    inner.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    outer = Table([[inner]], colWidths=[_CONTENT_W])
    outer.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _C_HINT_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, _C_HINT_BD),
        ("LINEBEFORE",    (0, 0), (0, -1),  3, _C_HINT_TX),
        ("LEFTPADDING",   (0, 0), (-1, -1), 12),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return outer


# ── Öffentliche API ───────────────────────────────────────────────────────────

def create_attack_scenario_section(
    elements: List,
    styles: Dict,
    technical_json: Optional[Dict[str, Any]] = None,
    context: Optional[Any] = None,
    **kwargs,
) -> None:
    """
    Rendert "Realistisches Angriffsszenario" als 4-stufige Angriffskette.

    Gate: Wenn ausschließlich Webdienste exponiert sind → Positiv-Box.
    """
    if technical_json is None and context is not None:
        technical_json = getattr(context, "technical_json", None) or {}
    if technical_json is None:
        technical_json = {}

    customer_name = ""
    if context is not None:
        customer_name = getattr(context, "customer_name", "") or ""

    intro_suffix = f" von {customer_name}" if customer_name else ""

    sec: List = []

    sec.append(Paragraph(
        "<b>Realistisches Angriffsszenario</b>",
        styles.get("heading1", styles.get("Heading1")),
    ))
    sec.append(Spacer(1, 6))
    web_only = _is_web_only(technical_json)
    if web_only:
        intro_text = (
            f'Bewertung der externen Angriffsfläche{intro_suffix} — '
            f'basierend auf den identifizierten offenen Diensten und bekannten Schwachstellen:'
        )
    else:
        intro_text = (
            f'So könnte ein realer Angriff auf die aktuelle Infrastruktur{intro_suffix} '
            f'ablaufen — basierend auf den identifizierten offenen Diensten und bekannten '
            f'Schwachstellen:'
        )

    sec.append(Paragraph(
        f'<font size="9" color="#555555">{intro_text}</font>',
        styles.get("Normal"),
    ))
    sec.append(Spacer(1, 10))

    if web_only:
        sec.append(_positive_box(styles))
    else:  # not web_only
        chain = _build_attack_chain(technical_json, context)
        for i, step in enumerate(chain):
            sec.append(_chain_card(step, styles))
            if i < len(chain) - 1:
                sec.append(Spacer(1, 6))
        sec.append(Spacer(1, 10))
        sec.append(_hinweis_box(styles))

    elements.append(keep_section(sec))
    elements.append(Spacer(1, 12))
