from typing import List, Dict, Any, Optional
import re
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from shodan_report.pdf.layout import keep_section, set_table_repeat
from shodan_report.pdf.sections.data.technical_data import prepare_technical_detail
from shodan_report.pdf.styles import Colors


def _clean_display_field(v: Optional[str], max_len: int = 80) -> str:
    if not v:
        return "-"
    s = str(v).strip()
    s = s.replace("\n", " ").replace("\r", " ")
    s = re.sub(r"\s+", " ", s)
    # redact long base64-like sequences (SSH keys)
    if re.search(r"[A-Za-z0-9+/]{40,}=*", s):
        return "[SSH-Key entfernt]"
    # remove leading numeric FTP/SMTP codes (e.g., '220 ')
    s = re.sub(r"^[0-9]{3}\s+", "", s)
    if len(s) > max_len:
        return s[: max_len - 3] + "..."
    return s


def _normalize_product(prod: Optional[str]) -> str:
    if not prod:
        return "-"
    p = str(prod).strip()
    low = p.lower()
    if "ssh-2.0" in low or "openssh" in low or "mod_sftp" in low or low.strip() == "ssh":
        if "mod_sftp" in low:
            return "SSH (mod_sftp)"
        return "SSH"
    # otherwise clean and truncate
    return _clean_display_field(p, max_len=60)


def _limit_list(items: List[str], max_items: int = 4) -> str:
    if not items:
        return ""
    trimmed = items[:max_items]
    suffix = " …" if len(items) > max_items else ""
    return ", ".join(trimmed) + suffix


# Known Shodan tags with security relevance, mapped to severity and readable label.
_SHODAN_TAG_MAP = {
    "eol-product":    ("hoch",    "End-of-Life-Produkt (generisches Signal) — kein Sicherheits-Patch-Zyklus mehr aktiv · Produkt-Details siehe EOL-Analyse unten"),
    "doublepulsar":   ("kritisch", "DoublePulsar-Backdoor erkannt (NSA-Exploit)"),
    "malware":        ("kritisch", "Malware-Aktivität von Shodan erkannt"),
    "honeypot":       ("mittel",   "Möglicher Honeypot — Ergebnisse mit Vorsicht interpretieren"),
    "tor":            ("mittel",   "TOR-Exit-Node — anonymisierter Datenverkehr möglich"),
    "self-signed":    ("niedrig",  "Selbstsigniertes Zertifikat — keine CA-Validierung"),
    "cloud":          (None,       "Cloud-gehostet"),
    "vpn":            (None,       "VPN-Dienst erkannt"),
}

_TAG_BG = {
    "kritisch": "#fef2f2",
    "hoch":     "#fff7ed",
    "mittel":   "#fefce8",
    "niedrig":  "#f0f9ff",
}
_TAG_BORDER = {
    "kritisch": "#ef4444",
    "hoch":     "#f97316",
    "mittel":   "#eab308",
    "niedrig":  "#3b82f6",
}
_TAG_LABEL = {
    "kritisch": "KRITISCH",
    "hoch":     "HOCH",
    "mittel":   "MITTEL",
    "niedrig":  "NIEDRIG (Info)",
}


def _render_shodan_tags_warning(
    elements: List, styles: Dict, technical_json: Dict[str, Any]
) -> None:
    """Render a warning box for security-relevant Shodan tags.
    Only shows tags that have a known severity mapping; informational tags
    (cloud, vpn) are skipped here — they stay in the metadata section.
    """
    tags = [str(t).lower().strip() for t in (technical_json.get("tags") or [])]
    if not tags:
        return

    # collect only tags with a severity
    relevant = []
    for tag in tags:
        entry = _SHODAN_TAG_MAP.get(tag)
        if entry and entry[0] is not None:
            relevant.append((tag, entry[0], entry[1]))

    if not relevant:
        return

    # sort by severity: kritisch > hoch > mittel > niedrig
    _order = {"kritisch": 0, "hoch": 1, "mittel": 2, "niedrig": 3}
    relevant.sort(key=lambda x: _order.get(x[1], 9))

    elements.append(Spacer(1, 6))
    for tag, sev, label in relevant:
        bg = HexColor(_TAG_BG[sev])
        border = HexColor(_TAG_BORDER[sev])
        sev_label = _TAG_LABEL[sev]
        cell_text = Paragraph(
            f"<b>Shodan-Tag [{sev_label}]:</b> {label}",
            styles["normal"],
        )
        box = Table([[cell_text]], colWidths=[163 * mm])
        box.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), bg),
            ("BOX",          (0, 0), (-1, -1), 1.0, border),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING",   (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ]))
        elements.append(box)
        elements.append(Spacer(1, 4))


def _render_eol_warnings(
    elements: List, styles: Dict, technical_json: Dict[str, Any]
) -> None:
    """Render warning boxes for EOL/near-EOL software detected in the services list."""
    try:
        from shodan_report.evaluation.eol import scan_services_for_eol
    except Exception:
        return

    services = list(technical_json.get("services") or technical_json.get("open_ports") or [])
    if not services:
        return

    # Normalise: services may store product/version nested under a "service" sub-dict
    # (from build_technical_data) or flat (from raw snapshots).  Produce a flat list
    # that scan_services_for_eol can consume.
    flat_services = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        sub = svc.get("service") or {}
        flat_services.append({
            "port":    svc.get("port"),
            "product": svc.get("product") or sub.get("product") or "",
            "version": svc.get("version") or sub.get("version") or "",
        })

    findings = scan_services_for_eol(flat_services)
    if not findings:
        return

    _STATUS_SEV = {"eol": "hoch", "near_eol": "mittel"}

    elements.append(Spacer(1, 4))
    for f in findings:
        sev = _STATUS_SEV.get(f["eol_status"], "niedrig")
        bg = HexColor(_TAG_BG[sev])
        border = HexColor(_TAG_BORDER[sev])
        sev_label = _TAG_LABEL[sev]

        display_name = f.get("display_name") or "Unbekanntes Produkt"
        eol_date = f.get("eol_date")
        note = f.get("note")
        confidence = f.get("confidence", "medium")
        port = f.get("port")
        support_model = f.get("support_model", "official")

        if f["eol_status"] == "eol" and eol_date:
            if support_model == "mainstream_end":
                msg = (
                    f"<b>EOL [{sev_label}]:</b> {display_name} — "
                    f"Mainstream-Support beendet seit {eol_date} (lizenzabhängig)"
                )
            else:
                msg = (
                    f"<b>EOL [{sev_label}]:</b> {display_name} — "
                    f"Sicherheits-Support beendet seit {eol_date}"
                )
        elif f["eol_status"] == "near_eol" and eol_date:
            if support_model == "mainstream_end":
                msg = (
                    f"<b>Near-EOL [{sev_label}]:</b> {display_name} — "
                    f"Mainstream-Support endet {eol_date} (lizenzabhängig)"
                )
            else:
                msg = (
                    f"<b>Near-EOL [{sev_label}]:</b> {display_name} — "
                    f"Sicherheits-Support endet {eol_date}"
                )
        else:
            msg = f"<b>EOL [{sev_label}]:</b> {display_name} — nicht mehr unterstützt"

        if note:
            msg += f". {note}"
        if confidence == "low":
            msg += " (Hinweis: Produkt erkannt, Version nicht auflösbar)"
        if port is not None:
            msg += f" · Port {port}"

        cell_text = Paragraph(msg, styles["normal"])
        box = Table([[cell_text]], colWidths=[163 * mm])
        box.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg),
            ("BOX",           (0, 0), (-1, -1), 1.0, border),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(box)
        elements.append(Spacer(1, 4))


# Insecure TLS/SSL protocol versions observed directly from TLS handshake data.
# These are VERIFIED findings — not inferred from version strings.
_TLS_INSECURE = {
    "SSLv2":   ("kritisch", "SSL 2.0 — vollständig kompromittiert, triviale Angriffe möglich"),
    "SSLv3":   ("kritisch", "SSL 3.0 — POODLE (CVE-2014-3566), vollständig kompromittiert"),
    "TLSv1":   ("hoch",     "TLS 1.0 — BEAST/POODLE, seit 2020 durch RFC 8996 abgekündigt"),
    "TLSv1.1": ("mittel",   "TLS 1.1 — bekannte kryptographische Schwächen, seit 2021 abgekündigt (RFC 8996)"),
}


def _render_tls_warnings(
    elements: List, styles: Dict, technical_json: Dict[str, Any]
) -> None:
    """Render VERIFIED warning boxes for insecure TLS protocol versions.

    Unlike EOL/CVE findings (inferred from version strings), these are
    directly observable from the Shodan TLS handshake data — no guessing.
    Shodan encodes: 'TLSv1' = enabled, '-TLSv1' = disabled (ignored here).
    """
    services = list(technical_json.get("services") or technical_json.get("open_ports") or [])
    if not services:
        return

    # Collect enabled insecure protocols → ports
    proto_ports: Dict[str, List] = {}
    for svc in services:
        if not isinstance(svc, dict):
            continue
        port = svc.get("port")
        ssl_info = svc.get("ssl_info") or {}
        if not isinstance(ssl_info, dict):
            continue
        for ver in (ssl_info.get("versions") or []):
            ver_str = str(ver).strip()
            if ver_str.startswith("-"):
                continue  # disabled — safe
            if ver_str in _TLS_INSECURE:
                entry = proto_ports.setdefault(ver_str, [])
                if port is not None and port not in entry:
                    entry.append(port)

    if not proto_ports:
        # TLS data was present but all insecure protocols disabled — show green OK box
        tls_checked_ports = [
            svc.get("port") for svc in services
            if isinstance(svc, dict) and isinstance(svc.get("ssl_info"), dict)
            and (svc["ssl_info"].get("versions") or [])
        ]
        if tls_checked_ports:
            ports_str = ", ".join(str(p) for p in sorted(set(p for p in tls_checked_ports if p is not None)))
            msg = (
                f"<b>TLS [VERIFIED] [OK]:</b> Direkt geprüft — alle unsicheren Protokolle "
                f"(SSLv2, SSLv3, TLSv1.0, TLSv1.1) deaktiviert · Port(s) {ports_str}"
            )
            bg = HexColor("#f0fdf4")       # green-50
            border = HexColor("#22c55e")   # green-500
            cell_text = Paragraph(msg, styles["normal"])
            box = Table([[cell_text]], colWidths=[163 * mm])
            box.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), bg),
                ("BOX",           (0, 0), (-1, -1), 1.0, border),
                ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("TOPPADDING",    (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            elements.append(Spacer(1, 4))
            elements.append(box)
            elements.append(Spacer(1, 4))
        return

    _order = {"kritisch": 0, "hoch": 1, "mittel": 2}
    sorted_protos = sorted(
        proto_ports.items(), key=lambda x: _order.get(_TLS_INSECURE[x[0]][0], 9)
    )

    elements.append(Spacer(1, 4))
    for proto, ports in sorted_protos:
        sev, label = _TLS_INSECURE[proto]
        bg = HexColor(_TAG_BG[sev])
        border = HexColor(_TAG_BORDER[sev])
        sev_label = _TAG_LABEL[sev]
        port_str = (
            f" · Port(s) {', '.join(str(p) for p in sorted(ports))}" if ports else ""
        )
        msg = f"<b>TLS [VERIFIED] [{sev_label}]:</b> {label}{port_str}"
        cell_text = Paragraph(msg, styles["normal"])
        box = Table([[cell_text]], colWidths=[163 * mm])
        box.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg),
            ("BOX",           (0, 0), (-1, -1), 1.0, border),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(box)
        elements.append(Spacer(1, 4))


def _find_insecure_tls(protocols: List[str]) -> List[str]:
    insecure = []
    for p in protocols or []:
        pl = str(p).lower().replace(" ", "")
        if "tls1.0" in pl or "tlsv1" in pl or "tlsv1.0" in pl:
            insecure.append("TLS 1.0")
        if "tls1.1" in pl or "tlsv1.1" in pl:
            insecure.append("TLS 1.1")
    # dedupe while preserving order
    out = []
    for item in insecure:
        if item not in out:
            out.append(item)
    return out


def _derive_risk_and_hint(
    s: Dict[str, Any], technical_json: Dict[str, Any]
) -> tuple:
    """
    Leitet Risiko-Level und Hinweistext für einen Service ab.
    Gibt (risk_str, hint_str) zurück.
    risk_str: "hoch" | "mittel" | "info"
    """
    port = s.get("port")
    prod = _normalize_product(s.get("product") or "")
    tls  = s.get("tls", {}) or {}

    # Risiko-Logik
    risk = "info"
    hints = []

    # Kritische Ports / Dienste
    if port in (3306, 5432, 1433, 27017):  # Datenbanken
        risk = "hoch"
        hints.append("Datenbank direkt exponiert · Firewall-Regel empfohlen")
    elif port in (21,):  # FTP
        days = tls.get("cert_expires_in_days")
        risk = "hoch"
        if isinstance(days, int) and 0 <= days <= 14:
            hints.append(f"Zertifikat läuft in {days} Tagen ab · Zugriff einschränken")
        else:
            hints.append("Zertifikat läuft ab · Zugriff einschränken")
    elif port in (2082, 2083, 2086, 2087):  # cPanel
        risk = "hoch"
        hints.append("Admin-Panel öffentlich erreichbar · IP-Whitelist empfohlen")
    elif port in (3389,):  # RDP
        risk = "hoch"
        hints.append("RDP direkt erreichbar · VPN/Jumphost empfohlen")
    elif port == 22:  # SSH
        risk = "mittel"
        ssh = s.get("ssh", {}) or {}
        kex = ssh.get("kex", [])
        macs = ssh.get("macs", [])
        parts = []
        if kex:
            parts.append(f"KEX: {kex[0]}" if kex else "")
        if macs:
            parts.append(f"MACs: {macs[0]}" if macs else "")
        parts.append("öffentlich erreichbar")
        hints.append(" · ".join(p for p in parts if p))
    elif port == 443:
        if tls.get("cert_self_signed"):
            risk = "mittel"
            issuer = tls.get("cert_issuer", "")
            cipher = ""
            if tls.get("ciphers"):
                cipher = f" · Cipher: {tls['ciphers'][0]}"
            hints.append(f"Selbstsigniertes Zertifikat · Aussteller: {issuer}{cipher}")
        else:
            risk = "info"
            hints.append("TLS aktiv · Zertifikat von CA signiert")
    elif port == 80:
        risk = "info"
        hints.append("Kein HTTPS-Redirect · HSTS nicht aktiv")

    # CVE-basiert upgraden
    cve_count = s.get("cve_count") or 0
    if cve_count > 0 and risk == "info":
        risk = "mittel"

    # Fallback Hinweis
    if not hints:
        ver = _clean_display_field(s.get("version") or "", max_len=40)
        if ver and ver != "-":
            hints.append(f"Version: {ver}")
        else:
            hints.append("—")

    return risk, " · ".join(hints[:2])  # max 2 Hinweise


def _risk_badge(styles: Dict, risk: str) -> Table:
    """
    Kleines farbiges Badge für die RISIKO-Spalte.
    hoch = rot, mittel = orange, info = grau
    """
    ns = styles.get("Normal") or styles.get("normal")
    cfg = {
        "hoch":   (Colors.risk_critical_bg,  Colors.risk_critical_dot,  "#991b1b", "hoch"),
        "mittel": (Colors.risk_high_bg,       Colors.risk_high_dot,      "#9a3412", "mittel"),
        "info":   (Colors.risk_unknown_bg,    Colors.border,             "#6b7280", "info"),
    }
    bg, bd, tx_hex, label = cfg.get(risk, cfg["info"])

    badge = Table(
        [[Paragraph(f'<font size="8" color="{tx_hex}"><b>{label}</b></font>', ns)]],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg),
        ("BOX",           (0, 0), (-1, -1), 0.7, bd),
        ("TOPPADDING",    (0, 0), (-1, -1), 0.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0.5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 2),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 2),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    return badge


def create_technical_section(elements: List, styles: Dict, *args, **kwargs) -> None:
    # Support DI call: create_technical_section(elements, styles, context=ctx)
    technical_json = kwargs.get("technical_json", {})
    evaluation = kwargs.get("evaluation", None)
    if "context" in kwargs and kwargs.get("context") is not None:
        ctx = kwargs.get("context")
        technical_json = getattr(ctx, "technical_json", technical_json)
        evaluation = getattr(ctx, "evaluation", evaluation)

    elements.append(Spacer(1, 12))
    heading_style = styles.get("heading1", styles.get("heading2"))
    elements.append(keep_section([
        Paragraph("<b>4. Technischer Anhang — Detailanalyse</b>", heading_style),
        Spacer(1, 8),
    ]))

    # Quellen-Hinweis (klein, grau)
    elements.append(Paragraph(
        '<font size="8" color="#888888">'
        "Quelle: Shodan (OSINT, passive Datenerhebung) · "
        "Alle Findings sind Inferred, sofern nicht als [VERIFIED] gekennzeichnet"
        "</font>",
        styles["normal"],
    ))
    elements.append(Spacer(1, 8))

    # Shodan-Tag-Warnings + EOL + TLS — unveränderte Logik, nur Pills nebeneinander
    _render_shodan_tags_warning(elements, styles, technical_json)
    _render_eol_warnings(elements, styles, technical_json)
    _render_tls_warnings(elements, styles, technical_json)

    if not technical_json:
        elements.append(Paragraph("Keine technischen Details verfügbar.", styles["normal"]))
        return

    data = prepare_technical_detail(technical_json or {}, evaluation)
    services = data.get("services", [])

    if not services:
        elements.append(Paragraph("Keine offenen Ports identifiziert.", styles["normal"]))
        return

    # ── Tabelle: PORT | DIENST | VERSION | RISIKO | HINWEIS ──────────────────
    _C_BORDER  = Colors.border     # #e5e7eb
    _C_HDR_BG  = Colors.bg_light   # #f8fafc
    _C_ROW_ALT = Colors.bg_stripe  # #f1f5f9

    def _hdr(text):
        return Paragraph(
            f'<font size="8" color="#6b7280"><b>{text}</b></font>',
            styles["normal"],
        )

    header = [_hdr("PORT"), _hdr("DIENST"), _hdr("VERSION"), _hdr("RISIKO"), _hdr("HINWEIS")]
    table_data = [header]
    seen_rows = set()

    for s in services:
        port_val = s.get("port") or "-"
        port_txt = str(port_val)
        prod_raw = s.get("product") or ""
        prod     = _normalize_product(prod_raw)
        ver_raw  = s.get("version") or ""
        ver      = _clean_display_field(ver_raw, max_len=40)
        if isinstance(ver, str):
            ver = ver.replace("\n", " ").replace("\r", " ").strip()

        key = (port_txt, str(prod))
        if key in seen_rows:
            continue
        seen_rows.add(key)

        # Risiko-Badge und Hinweis-Text ableiten
        risk, hint = _derive_risk_and_hint(s, technical_json)

        # Risiko-Badge als kleine farbige Table
        risk_cell = _risk_badge(styles, risk)

        table_data.append([
            Paragraph(f'<font size="9" color="#111827"><b>{port_txt}</b></font>', styles["normal"]),
            Paragraph(f'<font size="9" color="#111827">{prod}</font>',             styles["normal"]),
            Paragraph(f'<font size="9" color="#6b7280">{ver}</font>',              styles["normal"]),
            risk_cell,
            Paragraph(f'<font size="9" color="#111827">{hint}</font>',             styles["normal"]),
        ])

    # Spaltenbreiten: PORT | DIENST | VERSION | RISIKO | HINWEIS
    col_w = [14 * mm, 28 * mm, 34 * mm, 18 * mm, 81 * mm]
    tbl = Table(table_data, colWidths=col_w)
    set_table_repeat(tbl, 1)

    ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), _C_HDR_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, _C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, _C_BORDER),
        ("LINEBELOW",     (0, 0), (-1, 0),  0.5, _C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ])
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            ts.add("BACKGROUND", (0, i), (-1, i), _C_ROW_ALT)
    tbl.setStyle(ts)
    elements.append(tbl)
    elements.append(Spacer(1, 8))

    # Per-service details (TLS / SSH / Banner) — unveränderte Logik
    top_vulns_count = 0
    try:
        if isinstance(technical_json, dict):
            top_vulns_count = len(
                technical_json.get("vulns") or technical_json.get("vulnerabilities") or []
            )
    except Exception:
        top_vulns_count = 0

    for s in services:
        details = []
        tls = s.get("tls", {}) or {}
        if tls.get("protocols"):
            details.append(f"TLS-Protokolle: {', '.join(tls.get('protocols'))}")
            insecure_tls = _find_insecure_tls(tls.get("protocols") or [])
            if insecure_tls:
                details.append(f"Unsichere TLS-Versionen: {', '.join(insecure_tls)}")
        if tls.get("weak_ciphers"):
            details.append("Schwache Cipher/Konfiguration identifiziert")
        if tls.get("cert_expiry"):
            expiry_raw = tls.get("cert_expiry")
            days = tls.get("cert_expires_in_days")
            try:
                from dateutil import parser as _dtparser
                from datetime import timezone
                dt = None
                try:
                    dt = _dtparser.parse(str(expiry_raw))
                except Exception:
                    try:
                        from datetime import datetime as _dt
                        dt = _dt.strptime(str(expiry_raw), "%Y%m%d%H%M%SZ")
                        dt = dt.replace(tzinfo=timezone.utc)
                    except Exception:
                        dt = None
                fmt = dt.strftime("%d.%m.%Y") if dt else str(expiry_raw)
            except Exception:
                fmt = str(expiry_raw)
            if isinstance(days, int):
                label = f"abgelaufen vor {-days} Tagen" if days < 0 else f"in {days} Tagen"
                details.append(f"Zertifikat gültig bis: {fmt} ({label})")
            else:
                details.append(f"Zertifikat gültig bis: {fmt}")
        if tls.get("cert_valid_from"):
            valid_raw = tls.get("cert_valid_from")
            try:
                from dateutil import parser as _dtparser
                from datetime import timezone
                dt2 = None
                try:
                    dt2 = _dtparser.parse(str(valid_raw))
                except Exception:
                    try:
                        from datetime import datetime as _dt
                        dt2 = _dt.strptime(str(valid_raw), "%Y%m%d%H%M%SZ")
                        dt2 = dt2.replace(tzinfo=timezone.utc)
                    except Exception:
                        dt2 = None
                fmt2 = dt2.strftime("%d.%m.%Y") if dt2 else str(valid_raw)
            except Exception:
                fmt2 = str(valid_raw)
            details.append(f"Zertifikat gültig ab: {fmt2}")
        if tls.get("cert_issuer"):
            details.append(f"Zertifikat-Aussteller: {tls.get('cert_issuer')}")
        if tls.get("cert_self_signed") is True:
            details.append("Zertifikat: selbstsigniert")
        if tls.get("ciphers"):
            tls_ciphers = _limit_list(tls.get("ciphers") or [], max_items=4)
            if tls_ciphers:
                details.append(f"TLS-Cipher (Auszug): {tls_ciphers}")
        ssh = s.get("ssh", {}) or {}
        if ssh.get("version"):
            details.append(f"SSH-Software: {ssh.get('version')}")
        if ssh.get("auth"):
            auth_txt = _limit_list(ssh.get("auth") or [], max_items=3)
            if auth_txt:
                details.append(f"SSH-Authentifizierung: {auth_txt}")
        if ssh.get("kex"):
            kex_txt = _limit_list(ssh.get("kex") or [], max_items=3)
            if kex_txt:
                details.append(f"SSH-KEX: {kex_txt}")
        if ssh.get("ciphers"):
            cipher_txt = _limit_list(ssh.get("ciphers") or [], max_items=3)
            if cipher_txt:
                details.append(f"SSH-Cipher: {cipher_txt}")
        if ssh.get("macs"):
            mac_txt = _limit_list(ssh.get("macs") or [], max_items=3)
            if mac_txt:
                details.append(f"SSH-MACs: {mac_txt}")
        http = s.get("http", {}) or {}
        if http.get("hsts"):
            details.append("HSTS: aktiviert")
        if http.get("redirect_https"):
            details.append("HTTP→HTTPS-Redirect: erkennbar")
        if http.get("x_frame_options"):
            details.append("Security Header: X-Frame-Options")
        if http.get("csp"):
            details.append("Security Header: Content-Security-Policy")
        if http.get("x_content_type_options"):
            details.append("Security Header: X-Content-Type-Options")
        if http.get("methods"):
            methods_txt = _limit_list(http.get("methods") or [], max_items=6)
            if methods_txt:
                details.append(f"Erlaubte HTTP-Methoden: {methods_txt}")
            try:
                unsafe = [m for m in (http.get("methods") or []) if m.upper() in {"PUT", "DELETE", "TRACE"}]
                if unsafe:
                    details.append(f"Unsichere HTTP-Methoden: {', '.join(unsafe)}")
            except Exception:
                pass
        # Only show per-service CVE count when service has its own vulnerability list
        # Avoid repeating the host-level total for every service.
        svc_cve_count = s.get("cve_count") or 0
        if svc_cve_count and svc_cve_count != top_vulns_count:
            details.append(f"Bekannte Schwachstellen: {svc_cve_count} (hoch: {s.get('high_cvss')})")
        if s.get("banner"):
            b = s.get("banner")
            if isinstance(b, str) and len(b) > 0:
                short = b.replace('\n', ' ').strip()
                if len(short) > 140:
                    short = short[:137] + "..."
                details.append(f"Banner: {short}")

        # Recompute display product/version per-service to avoid using loop-scoped vars
        prod_raw = s.get("product") or ""
        prod = _normalize_product(prod_raw)
        ver_raw = s.get("version") or ""
        ver = _clean_display_field(ver_raw, max_len=60)

        if details:
            header_line = f"Port {s.get('port')}: {prod} ({ver})"
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(f"<b>{header_line}</b>", styles["normal"]))
            for d in details:
                elements.append(Paragraph(f"• {d}", styles["bullet"]))

    # 3. System-Metadaten
    _add_system_metadata(elements, styles, technical_json)

    # 4. Sicherheitshinweise entfernt (Technischer Anhang enthält nur Fakten)


def _add_port_information(elements: List, styles: Dict, open_ports: List[Dict]) -> None:
    elements.append(
        Paragraph("<b>Öffentlich erreichbare Dienste:</b>", styles["normal"])
    )
    elements.append(Spacer(1, 4))

    seen_ports = set()
    for port_info in open_ports:
        port = port_info.get("port", "?")
        transport = port_info.get("transport", "tcp").upper()

        port_key = f"{port}/{transport}"
        if port_key in seen_ports:
            continue
        seen_ports.add(port_key)

        service = port_info.get("service", {})
        product = service.get("product", "Unbekannter Dienst")
        version = service.get("version", "")
        banner = service.get("banner", "")
        extra_info = port_info.get("extra_info", "")

        port_text = _build_port_text(
            port, transport, product, version, banner, extra_info
        )
        elements.append(Paragraph(f"• {port_text}", styles["bullet"]))


def _build_port_text(
    port: int, transport: str, product: str, version: str, banner: str, extra_info: str
) -> str:
    port_text_parts = [f"<b>Port {port}/{transport}:</b> {product}"]

    # Version hinzufügen
    if version and version.strip():
        clean_version = version.strip().replace("\n", " ").replace("\r", "")
        if len(clean_version) < 40:
            port_text_parts.append(f"({clean_version})")

    # Extra-Informationen
    if extra_info:
        port_text_parts.append(f"<i>{extra_info}</i>")

    # Banner-Vorschau
    if banner and len(banner.strip()) > 0:
        clean_banner = banner.strip().replace("\n", " ").replace("\r", "")
        if len(clean_banner) < 80 and not any(
            x in clean_banner.lower() for x in ["<", ">", "{", "}"]
        ):
            port_text_parts.append(f"»{clean_banner}«")

    return " ".join(port_text_parts)


def _add_system_metadata(
    elements: List, styles: Dict, technical_json: Dict[str, Any]
) -> None:
    """System-Informationen als zweispaltiges Grid — wie im Screenshot."""
    elements.append(Spacer(1, 12))

    # Label-Zeile
    elements.append(Paragraph(
        '<font size="9" color="#6b7280"><b>SYSTEM-INFORMATIONEN</b></font>',
        styles["normal"],
    ))
    elements.append(Spacer(1, 6))

    items = _extract_metadata_items_structured(technical_json)
    if not items:
        elements.append(Paragraph("Keine weiteren Metadaten verfügbar.", styles["normal"]))
        return

    # Zweispaltig: linke Spalte + rechte Spalte
    # Aufteilen: erste Hälfte links, zweite Hälfte rechts
    half = (len(items) + 1) // 2
    left_items  = items[:half]
    right_items = items[half:]

    # Auf gleiche Länge padden
    while len(right_items) < len(left_items):
        right_items.append(("", ""))

    _C_LABEL = "#6b7280"   # Colors.text_muted
    _C_VAL   = "#111827"   # Colors.text
    ns = styles.get("Normal") or styles.get("normal")

    def _row(label, val):
        return [
            Paragraph(f'<font size="9" color="{_C_LABEL}">{label}</font>', ns),
            Paragraph(f'<font size="9" color="{_C_VAL}"><b>{val}</b></font>', ns),
        ]

    rows = []
    for (ll, lv), (rl, rv) in zip(left_items, right_items):
        rows.append(_row(ll, lv) + _row(rl, rv))

    col_w = [38 * mm, 48 * mm, 38 * mm, 51 * mm]
    tbl = Table(rows, colWidths=col_w)
    tbl.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.3, HexColor("#EEEEEE")),
    ]))
    elements.append(tbl)


def _extract_metadata_items_structured(
    technical_json: Dict[str, Any],
) -> List[tuple]:
    """Gibt Liste von (label, value) Tupeln zurück — für zweispaltiges Grid."""
    items = []

    hostnames = technical_json.get("hostnames", [])
    if hostnames:
        items.append(("Hostname(s)", ", ".join(hostnames[:2])))

    org = technical_json.get("org", "")
    isp = technical_json.get("isp", "")
    if org:
        items.append(("Organisation", org))
    elif isp:
        items.append(("ISP", isp))

    asn = technical_json.get("asn", "")
    if asn:
        items.append(("Autonomous System", str(asn)))

    country = technical_json.get("country", "")
    city    = technical_json.get("city", "")
    if country and city:
        items.append(("Standort", f"{city}, {country}"))
    elif country:
        items.append(("Land", country))

    # Tags (informational only)
    tags = [str(t).lower().strip() for t in (technical_json.get("tags") or [])]
    info_tags = [t for t in tags if _SHODAN_TAG_MAP.get(t, (None,))[0] is None and t not in _SHODAN_TAG_MAP]
    info_tags += [t for t in tags if t in _SHODAN_TAG_MAP and _SHODAN_TAG_MAP[t][0] is None]
    if info_tags:
        items.append(("Tags", " · ".join(info_tags)))

    vulnerabilities = technical_json.get("vulnerabilities", [])
    if vulnerabilities:
        items.append(("Schwachstellen (Inferred)", str(len(vulnerabilities))))

    critical_services = technical_json.get("critical_services", [])
    if critical_services:
        high_critical = [c for c in critical_services if c.get("severity") == "high"]
        if high_critical:
            items.append(("Krit. Konfigurationen", str(len(high_critical))))

    return items


def _extract_metadata_items(technical_json: Dict[str, Any]) -> List[str]:
    """Flat string list wrapper around _extract_metadata_items_structured."""
    return [f"{label}: {value}" for label, value in _extract_metadata_items_structured(technical_json)]


def _add_security_notes(
    elements: List, styles: Dict, technical_json: Dict[str, Any]
) -> None:
    critical_services = technical_json.get("critical_services", [])

    if not critical_services:
        return

    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>Sicherheitshinweise:</b>", styles["normal"]))
    elements.append(Spacer(1, 4))

    for critical in critical_services[:3]:  # Max 3 Hinweise
        port = critical.get("port", "")
        reason = critical.get("reason", "")
        # Remove stray debug tokens like 'nn' that may appear in snapshots
        try:
            reason = str(reason).replace("nn ", "").replace("nn", "").strip()
        except Exception:
            pass
        severity = critical.get("severity", "medium")

        severity_label = "Achtung" if severity == "high" else "Hinweis"
        elements.append(
            Paragraph(f"{severity_label}: Port {port}: {reason}", styles["bullet"])
        )