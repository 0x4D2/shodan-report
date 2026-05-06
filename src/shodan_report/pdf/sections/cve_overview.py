"""
CVE- & Exploit-Übersicht für PDF-Reports - KOMPAKTE VERSION für One-Page Design.
"""

import re
import os
from typing import List, Dict, Any, Optional
from reportlab.platypus import Spacer, Paragraph, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import HexColor
from shodan_report.pdf.layout import keep_section, set_table_repeat, set_table_no_split
try:
    from ..sections.data.cve_enricher import enrich_cves
except Exception:
    # If the enricher module fails to import (temporary local corruption),
    # provide a minimal fallback so PDF generation can proceed.
    def enrich_cves(*args, **kwargs):
        ids = []
        if len(args) >= 1 and isinstance(args[0], (list, tuple)):
            ids = list(args[0])
        elif 'cve_ids' in kwargs:
            ids = list(kwargs.get('cve_ids') or [])
        else:
            ids = []
        return [{'id': str(i), 'nvd_url': f'https://nvd.nist.gov/vuln/detail/{i}', 'cvss': None, 'ports': []} for i in ids]


def _get_style(styles: Dict, name: str, fallback: str = "normal"):
    """Safely get a style by name with fallback."""
    if not isinstance(styles, dict):
        return None
    return styles.get(name) or styles.get(fallback)


def create_cve_overview_section(
    elements: List,
    styles: Dict,
    technical_json: Dict[str, Any],
    evaluation: Optional[Dict[str, Any]] = None,
    context: Optional[Any] = None,
) -> None:
    """
    CVE-Übersicht — Design wie im Screenshot:
    5 KPI-Karten oben · CVSS-Balken · Inferred-Hinweis · Tabelle · Fußnoten-Box.
    """
    elements.append(Spacer(1, 8))
    heading_style = styles.get("heading1", styles.get("heading2"))
    elements.append(keep_section([
        Paragraph("<b>6. CVE-Übersicht</b>", heading_style),
        Spacer(1, 10),
    ]))

    cve_data = _extract_cve_data(technical_json, context)

    # Prominente Warnbox — vor den KPI-Karten, damit klar ist: das sind Verdachtsmomente
    _create_inferred_warning(elements, styles)

    if not cve_data:
        elements.append(Paragraph(
            "Keine CVE-basierten Exploit-Risiken identifiziert; "
            "das Risiko ergibt sich jedoch aus der direkten Exposition des Dienstes.",
            styles["normal"],
        ))
        return

    # Drei-Stufen-Confidence: CVEs nach confidence aufteilen.
    # UNMATCHED  → eigener Abschnitt unten (kein Mapping möglich)
    # low_confidence (Bug 2, platform-only) → separater Warnabschnitt
    # VERIFIED + INFERRED → Hauptliste
    try:
        from shodan_report.pdf.sections.data.cve_enricher import MatchConfidence
        _unmatched_val = MatchConfidence.UNMATCHED
    except Exception:
        _unmatched_val = None

    def _is_unmatched(c):
        conf = c.get("confidence")
        if conf is None:
            return False
        if _unmatched_val is not None and conf == _unmatched_val:
            return True
        # Fallback: String-Vergleich wenn Enum-Import fehlschlägt
        return str(conf).lower() in ("unmatched", "matchconfidence.unmatched")

    cve_data_unmatched = [c for c in cve_data if _is_unmatched(c) and not c.get("low_confidence")]
    cve_data_low       = [c for c in cve_data if c.get("low_confidence")]
    cve_data_main      = [c for c in cve_data if not _is_unmatched(c) and not c.get("low_confidence")]

    # Hauptliste leer → alle zeigen (Fallback: kein Filter wirksam)
    if not cve_data_main and (cve_data_unmatched or cve_data_low):
        cve_data_main      = cve_data
        cve_data_unmatched = []
        cve_data_low       = []

    # 1. KPI-Karten (nur verifizierbare CVEs)
    _create_risk_overview(elements, styles, cve_data_main)

    # 2. CVSS-Verteilungsbalken
    _create_cvss_bar(elements, cve_data_main)

    # 3. Confidence-Hinweis
    try:
        from shodan_report.pdf.sections.data.cve_enricher import MatchConfidence
        _verified_count  = sum(1 for c in cve_data_main if c.get("confidence") == MatchConfidence.VERIFIED)
        _inferred_count  = sum(1 for c in cve_data_main if c.get("confidence") == MatchConfidence.INFERRED)
        _unmatched_total = len(cve_data_unmatched)
    except Exception:
        _verified_count = _inferred_count = _unmatched_total = 0

    _parts = []
    if _verified_count:
        _parts.append(f'<font color="#166534"><b>{_verified_count} Verified</b></font>')
    if _inferred_count:
        _parts.append(f'<font color="#92400e"><b>{_inferred_count} Inferred</b></font>')
    if _unmatched_total:
        _parts.append(f'<font color="#888888">{_unmatched_total} nicht zuordenbar</font>')
    _hint_inner = " · ".join(_parts) if _parts else f"{len(cve_data_main)} CVEs"

    elements.append(Spacer(1, 6))
    elements.append(Paragraph(
        f'<font size="9">{_hint_inner}</font>',
        styles["normal"],
    ))
    elements.append(Spacer(1, 8))

    # 4. Tabelle (nur Haupt-CVEs)
    show_full = False
    limit = 6
    try:
        if context is not None:
            show_full = bool(getattr(context, "show_full_cve_list", False))
            limit = int(getattr(context, "cve_limit", 10) or 10)
    except Exception:
        show_full = False
        limit = 10

    _create_detailed_cve_table(elements, styles, cve_data_main, technical_json,
                               show_full=show_full, limit=limit)

    # 5. Fußnoten-Box
    _final_evaluation_paragraph(elements, styles, cve_data_main)

    # 6. Separater Abschnitt für UNMATCHED CVEs (kein Dienst-Mapping möglich)
    if cve_data_unmatched:
        _create_unmatched_cve_note(elements, styles, cve_data_unmatched)

    # 7. BUGFIX: Bug 2 — Separater Abschnitt für low_confidence CVEs (platform-only)
    if cve_data_low:
        _create_low_confidence_cve_note(elements, styles, cve_data_low)


def _extract_cve_data(technical_json: Dict[str, Any], context: Optional[Any] = None) -> List[Dict]:
    """Extrahiert CVE-Daten aus technical_json.

    Nutzt lokalen Enricher (`enrich_cves`) um CVSS und betroffene Ports zu ermitteln,
    falls diese Informationen in `technical_json` vorhanden sind.
    """

    # Sammle Kandidaten-CVE-IDs aus möglichen Feldern
    ids = set()
    if isinstance(technical_json, dict):
        # top-level vulns
        for k in ("vulnerabilities", "vulns", "vulns_list", "vulns"):
            for v in technical_json.get(k, []) or []:
                if isinstance(v, str):
                    ids.add(v)
                elif isinstance(v, dict):
                    cid = v.get("id") or v.get("cve") or v.get("cve_id")
                    if cid:
                        ids.add(str(cid))

        # per-service
        services = technical_json.get("services") or technical_json.get("open_ports") or []
        for s in services:
            sv_vulns = []
            if isinstance(s, dict):
                sv_vulns = s.get("vulnerabilities") or s.get("vulns") or s.get("cves") or []
            else:
                # service may be an int (port), a string, or an object-like with attributes
                try:
                    sv_vulns = getattr(s, "vulnerabilities", None) or getattr(s, "vulns", None) or getattr(s, "cves", None) or []
                except Exception:
                    sv_vulns = []

            if not sv_vulns:
                continue

            for vv in sv_vulns:
                if isinstance(vv, str):
                    ids.add(vv)
                elif isinstance(vv, dict):
                    cid = vv.get("id") or vv.get("cve") or vv.get("cve_id")
                    if cid:
                        ids.add(str(cid))

    unique_ids = sorted(ids)

    # Enrich locally: get cvss and ports if available
    # Allow live NVD lookups via env or config
    lookup_nvd = False
    try:
        if context is not None and hasattr(context, "config"):
            cfg = getattr(context, "config") or {}
            lookup_nvd = bool((cfg.get("nvd") or {}).get("enabled", False))
    except Exception:
        lookup_nvd = False
    if os.environ.get("NVD_LIVE") == "1":
        lookup_nvd = True

    enriched = enrich_cves(unique_ids, technical_json, lookup_nvd=lookup_nvd)

    cve_data = []
    for ent in enriched:
        try:
            cid = ent.get("id")
            raw_cvss = ent.get("cvss")
            # Treat missing/empty cvss as unknown (None) rather than 0
            if raw_cvss is None or raw_cvss == "" or str(raw_cvss).lower() in ("n/a", "na"):
                cvss_val = None
            else:
                try:
                    cvss_val = float(raw_cvss)
                except Exception:
                    cvss_val = None

            ports = ent.get("ports", []) or []
            service = ",".join([str(p) for p in ports]) if ports else "Various"
            # Preserve NVD url and any service indicator populated by the enricher
            # ExploitDB + EPSS aus technical_json mergen (vom Runner befüllt)
            _exploit_map = technical_json.get("cve_exploit_map") or {} if isinstance(technical_json, dict) else {}
            _epss_map    = technical_json.get("cve_epss_map")    or {} if isinstance(technical_json, dict) else {}
            _exploitdb   = bool(_exploit_map.get(str(cid or "").upper()))
            _epss_score  = _epss_map.get(str(cid or "").upper())

            cve_entry = {
                "id": cid,
                "cvss": cvss_val,
                "ports": ports,
                "service": service[:40],
                "summary": ent.get("summary") or "",
                "exploit_status": ent.get("exploit_status", "unknown"),
                "exploitdb": _exploitdb,
                "epss_score": float(_epss_score) if _epss_score is not None else None,
                "nvd_url": ent.get("nvd_url") or f'https://nvd.nist.gov/vuln/detail/{cid}',
            }
            # optional structured indicator from CPE helper
            if ent.get("service_indicator"):
                cve_entry["service_indicator"] = ent.get("service_indicator")
                ind_label = None
                try:
                    ind_label = ent.get("service_indicator", {}).get("label")
                except Exception:
                    ind_label = None
                if service == "Various" and ind_label:
                    service = ind_label
                    cve_entry["service"] = service
            if ent.get("service_evidence"):
                cve_entry["service_evidence"] = ent.get("service_evidence")
            cve_data.append(cve_entry)
        except Exception:
            continue

    return cve_data


def _create_inferred_warning(elements: List, styles: Dict) -> None:
    """Amber-Warnbox: macht visuell klar, dass CVEs OSINT-Verdachtsmomente sind."""
    ns = styles.get("normal") or styles.get("Normal")
    box = Table([[Paragraph(
        '<font size="8" color="#92400e"><b>OSINT-Indizien — keine aktive Prüfung</b></font><br/>'
        '<font size="8" color="#78350f">'
        'Alle Schwachstellen basieren auf Versionserkennung (Shodan). '
        'Ein Treffer bedeutet: diese Softwareversion ist laut NVD theoretisch anf\xe4llig — '
        '<b>nicht</b>, dass der Exploit auf diesem System funktioniert. '
        'VERIFIED = direkt messbar (z. B. TLS-Protokoll) · '
        'INFERRED = Versionsmatch, nicht best\xe4tigt.'
        '</font>',
        ns,
    )]], colWidths=[175 * mm])
    box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#FFFBEB")),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#F59E0B")),
        ("LINEBEFORE",    (0, 0), (0, -1),  4,   HexColor("#F59E0B")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    elements.append(box)
    elements.append(Spacer(1, 8))


def _confidence_label(confidence) -> tuple:
    """Gibt (label, hex_color) für einen Confidence-Wert zurück."""
    try:
        from shodan_report.pdf.sections.data.cve_enricher import MatchConfidence
        if confidence == MatchConfidence.VERIFIED:
            return "VERIFIED", "#166534"
        if confidence == MatchConfidence.INFERRED:
            return "INFERRED", "#92400e"
    except Exception:
        pass
    s = str(confidence).lower()
    if "verified" in s:
        return "VERIFIED", "#166534"
    if "inferred" in s:
        return "INFERRED", "#92400e"
    return "OSINT", "#888888"


def _create_risk_overview(elements: List, styles: Dict, cve_data: List[Dict]) -> None:
    """
    Fünf KPI-Karten nebeneinander — wie im Screenshot:
    große Zahl in Farbe, darunter kleines Uppercase-Label.
    """
    ns = styles.get("normal") or styles.get("Normal")

    critical = len([c for c in cve_data if c.get("cvss") is not None and c.get("cvss") >= 9.0])
    high     = len([c for c in cve_data if c.get("cvss") is not None and 7.0 <= c.get("cvss") < 9.0])
    medium   = len([c for c in cve_data if c.get("cvss") is not None and 4.0 <= c.get("cvss") < 7.0])
    low      = len([c for c in cve_data if c.get("cvss") is not None and c.get("cvss") < 4.0])
    cisa_kev = len([c for c in cve_data if c.get("exploit_status") == "public"])

    _C_BORDER = HexColor("#DDDDDD")
    _C_BG     = HexColor("#F8F8F8")

    def _card(num, label, num_color):
        # Beide Paragraphen werden explizit zentriert
        num_paragraph = Paragraph(
            f'<para align="center"><font size="18" color="{num_color}"><b>{num}</b></font></para>', ns)
        label_paragraph = Paragraph(
            f'<para align="center"><font size="7" color="#888888">{label}</font></para>', ns)
        inner = Table([
            [num_paragraph],
            [label_paragraph],
        ], colWidths=[34 * mm])
        inner.setStyle(TableStyle([
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ]))
        return inner

    cards = [
        _card(critical, "KRITISCH (≥9)",   "#C0392B"),
        _card(high,     "HOCH (7–8.9)",    "#E67E22"),
        _card(medium,   "MEDIUM (4–6.9)",  "#F39C12"),
        _card(low,      "NIEDRIG (<4)",    "#888888"),
        _card(cisa_kev, "CISA KEV",        "#1A1A1A"),
    ]

    row_tbl = Table([[c for c in cards]], colWidths=[35 * mm] * 5)
    row_tbl.setStyle(TableStyle([
        ("BOX",           (0, 0), (-1, -1), 0.5, _C_BORDER),
        ("LINEBEFORE",    (1, 0), (-1, -1), 0.5, _C_BORDER),
        ("BACKGROUND",    (0, 0), (-1, -1), _C_BG),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    elements.append(row_tbl)
    elements.append(Spacer(1, 8))


def _create_cvss_bar(elements: List, cve_data: List[Dict]) -> None:
    """
    Horizontaler CVSS-Verteilungsbalken — rot/orange/gelb/grau proportional.
    """
    total = len(cve_data)
    if total == 0:
        return

    critical = len([c for c in cve_data if c.get("cvss") is not None and c.get("cvss") >= 9.0])
    high     = len([c for c in cve_data if c.get("cvss") is not None and 7.0 <= c.get("cvss") < 9.0])
    medium   = len([c for c in cve_data if c.get("cvss") is not None and 4.0 <= c.get("cvss") < 7.0])
    rest     = total - critical - high - medium

    full_w = 175 * mm
    segs = []
    for count, color in [
        (critical, "#C0392B"),
        (high,     "#E67E22"),
        (medium,   "#F39C12"),
        (rest,     "#CCCCCC"),
    ]:
        if count > 0:
            w = (count / total) * full_w
            segs.append((w, color))

    if not segs:
        return

    # Baue Balken als einzeilige Tabelle mit farbigen Zellen
    cells  = [Paragraph("", ParagraphStyle("x", fontSize=1)) for _ in segs]
    widths = [s[0] for s in segs]
    bar    = Table([cells], colWidths=widths)

    ts = TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ])
    for i, (_, color) in enumerate(segs):
        ts.add("BACKGROUND", (i, 0), (i, 0), HexColor(color))
    bar.setStyle(ts)

    # Wrapper für feste Höhe (6pt)
    wrapper = Table([[bar]], colWidths=[full_w])
    wrapper.setStyle(TableStyle([
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("ROWHEIGHT",     (0, 0), (-1, -1), 6),
    ]))
    elements.append(wrapper)


def _create_risk_cell(label: str, count: int, color) -> Paragraph:
    """Erstelle eine Risiko-Zelle für die Übersicht."""
    # label bold, count emphasized with larger bold font for readability
    # Make label slightly smaller and the numeric count modestly larger but reduced
    # from previous values to avoid visual dominance.
    text = f"<font size=7><b>{label}</b></font><br/><font size=8><b>{count}</b></font>"
    return Paragraph(
        text,
        style=ParagraphStyle(
            "RiskCell",
            alignment=1,  # Center
            textColor=colors.white,
            fontSize=7,
            leading=8,
            spaceBefore=0,
            spaceAfter=0,
        ),
    )


def _create_compact_cve_table(
    elements: List, styles: Dict, cve_data: List[Dict]
) -> None:
    """Erstelle kompakte CVE-Tabelle mit Farbcodierung."""

    # Sortiere nach CVSS (höchste zuerst) and keep Top 6; treat None as lowest
    def _sort_key(x):
        v = x.get("cvss")
        return v if v is not None else -1

    sorted_cves = sorted(cve_data, key=_sort_key, reverse=True)[:6]

    if not sorted_cves:
        return

    # Tabellen-Header (kompakt)
    table_data = [
        [
            Paragraph("<b>CVE ID</b>", styles["normal"]),
            Paragraph("<b>CVSS</b>", styles["normal"]),
            Paragraph("<b>Service</b>", styles["normal"]),
            Paragraph("<b>Exploit</b>", styles["normal"]),
        ]
    ]

    # Datenzeilen mit Farbcodierung
    for cve in sorted_cves:
        cvss = cve.get("cvss")

        # Bestimme Farbe basierend auf CVSS; unknown -> neutral
        if cvss is None:
            bg_color = colors.white
            text_color = colors.HexColor("#374151")
        elif cvss >= 9.0:
            bg_color = colors.HexColor("#fee2e2")  # Hellrot
            text_color = colors.HexColor("#991b1b")
        elif cvss >= 7.0:
            bg_color = colors.HexColor("#ffedd5")  # Hellorange
            text_color = colors.HexColor("#9a3412")
        elif cvss >= 4.0:
            bg_color = colors.HexColor("#fef9c3")  # Hellgelb
            text_color = colors.HexColor("#854d0e")
        else:
            bg_color = colors.HexColor("#dcfce7")  # Hellgrün
            text_color = colors.HexColor("#166534")

        # Exploit Status Icon
        exploit_status = cve.get("exploit_status", "unknown")
        exploit_icon = {
            "public": "🔴",
            "private": "🟡",
            "none": "🟢",
            "unknown": "⚪",
        }.get(exploit_status, "⚪")

        # Zellen mit minimalem Inhalt
        table_data.append(
            [
                Paragraph(
                    f"<font color='{text_color.hexval()}'>{cve['id']}</font>",
                    styles["normal"],
                ),
                Paragraph(
                    f"<font color='{text_color.hexval()}'><b>{cvss if cvss is not None else 'n/a'}</b></font>",
                    styles["normal"],
                ),
                Paragraph(
                    f"<font color='{text_color.hexval()}'>{cve['service']}</font>",
                    styles["normal"],
                ),
                Paragraph(exploit_icon, styles["normal"]),
            ]
        )

    # Tabelle erstellen (kompakt) — setze Spaltenbreiten so, dass Dienste
    # genügend Platz haben, aber die Tabelle nicht zu breit wird.
    col_widths = [35 * mm, 20 * mm, 45 * mm, 15 * mm]

    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    set_table_no_split(table)

    # Styling für kompakte Tabelle
    table_style = TableStyle(
        [
            # Header
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            # Grid
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            # Mehr Padding, damit längere Texte nicht visuell abgeschnitten wirken
            ("PADDING", (0, 0), (-1, -1), (4, 2)),
            # Zeilen-Hintergrund für bessere Lesbarkeit
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.white, colors.HexColor("#f9fafb")],
            ),
            # Alignment
            ("ALIGNMENT", (1, 1), (1, -1), "CENTER"),  # CVSS zentrieren
            ("ALIGNMENT", (3, 1), (3, -1), "CENTER"),  # Exploit Icon zentrieren
        ]
    )

    # Individuelle Zellen-Hintergründe für CVEs
    for i, cve in enumerate(sorted_cves, start=1):  # i=1 wegen Header
        cvss = cve.get("cvss")
        if cvss is None:
            continue
        if cvss >= 9.0:
            table_style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fee2e2"))
        elif cvss >= 7.0:
            table_style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#ffedd5"))
        elif cvss >= 4.0:
            table_style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fef9c3"))

    table.setStyle(table_style)
    elements.append(table)
    elements.append(Spacer(1, 4))

    # Hinweis für viele CVEs (kompakt)
    total_cves = len(cve_data)
    if total_cves > 6:
        elements.append(
            Paragraph(
                f"<i>... und {total_cves - 6} weitere CVEs</i>",
                ParagraphStyle(
                    "SmallItalic",
                    parent=styles["normal"],
                    fontSize=7,
                    textColor=colors.grey,
                ),
            )
        )


def _create_exploit_summary(elements: List, styles: Dict, cve_data: List[Dict]) -> None:
    """Erstelle kompakte Exploit-Zusammenfassung."""

    # Zähle Exploit-Status
    exploit_counts = {"public": 0, "private": 0, "none": 0, "unknown": 0}

    for cve in cve_data:
        status = cve.get("exploit_status", "unknown")
        if status in exploit_counts:
            exploit_counts[status] += 1

    # Kompakte einzeilige Darstellung
    summary_parts = []
    if exploit_counts["public"] > 0:
        summary_parts.append(f"🔴 {exploit_counts['public']} public")
    if exploit_counts["private"] > 0:
        summary_parts.append(f"🟡 {exploit_counts['private']} private")
    if exploit_counts["none"] > 0:
        summary_parts.append(f"🟢 {exploit_counts['none']} none")
    if exploit_counts["unknown"] > 0:
        summary_parts.append(f"⚪ {exploit_counts['unknown']} unknown")

    if summary_parts:
        elements.append(
            Paragraph(
                f"<b>Exploits:</b> {' | '.join(summary_parts)}",
                ParagraphStyle(
                    "SmallSummary",
                    parent=styles["normal"],
                    fontSize=8,
                    textColor=colors.HexColor("#4b5563"),
                ),
            )
        )


def _create_detailed_cve_table(
    elements: List,
    styles: Dict,
    cve_data: List[Dict],
    technical_json: Dict[str, Any],
    *,
    show_full: bool = False,
    limit: int = 6,
) -> None:
    """
    Tabelle: CVE | CVSS-Badge | DIENST/KOMPONENTE | EXPLOIT-STATUS | RELEVANZ-Badge
    Exakt wie im Screenshot — CVE-ID linksbündig, CVSS als farbiges Badge,
    RELEVANZ als farbiges Badge, Zeilen ohne farbigen Hintergrund.
    """
    if not cve_data:
        return

    ns = styles.get("normal") or styles.get("Normal")
    _C_BORDER  = HexColor("#DDDDDD")
    _C_HDR_BG  = HexColor("#F8F8F8")
    _C_ROW_ALT = HexColor("#F8FAFC")

    # Port→Produktname aufbauen
    port_product = {}
    try:
        services_src = (
            technical_json.get("services") or technical_json.get("open_ports") or []
            if isinstance(technical_json, dict) else []
        )
        for s in services_src:
            if not isinstance(s, dict):
                continue
            p    = s.get("port")
            prod = None
            if isinstance(s.get("service"), dict):
                prod = s["service"].get("product") or s["service"].get("name")
            prod = prod or s.get("product") or s.get("service") or s.get("name")
            if isinstance(prod, dict):
                prod = prod.get("product") or prod.get("name") or str(p)
            if p is not None:
                port_product[p] = str(prod).strip() if prod else str(p)
    except Exception:
        pass

    def _hdr(text):
        return Paragraph(
            f'<font size="8" color="#666666"><b>{text}</b></font>', ns
        )

    rows = [[
        _hdr("CVE"),
        _hdr("CVSS"),
        _hdr("DIENST / KOMPONENTE"),
        _hdr("EXPLOIT"),
        _hdr("EPSS (30T)"),
    ]]

    # Sortieren: CISA KEV > ExploitDB > service_indicator > CVSS
    def _sort_key(x):
        v = x.get("cvss")
        is_kev     = 1 if x.get("exploit_status") == "public" else 0
        has_exploit = 1 if x.get("exploitdb") else 0
        has_ind    = 1 if x.get("service_indicator") else 0
        return (is_kev, has_exploit, has_ind, v if v is not None else -1)

    sorted_all  = sorted(cve_data, key=_sort_key, reverse=True)
    to_display  = sorted_all if show_full else sorted_all[:max(0, int(limit or 6))]
    remaining   = len(sorted_all) - len(to_display)

    for c in to_display:
        cid  = c.get("id") or "—"
        cvss = c.get("cvss")
        exploit = c.get("exploit_status", "unknown")

        # CVE-Zelle: ID + Confidence-Badge in zweiter Zeile
        conf_label, conf_color = _confidence_label(c.get("confidence"))
        nvd_url = c.get("nvd_url")
        id_markup = (
            f'<font size="9" color="#2563A8"><a href="{nvd_url}">{cid}</a></font>'
            if nvd_url else
            f'<font size="9" color="#1A1A1A">{cid}</font>'
        )
        cve_cell = Paragraph(
            f'{id_markup}<br/>'
            f'<font size="7" color="{conf_color}">{conf_label}</font>',
            ns,
        )

        # CVSS-Badge
        cvss_cell = _cvss_badge(styles, cvss)

        # Dienst/Komponente
        try:
            ind = c.get("service_indicator")
            ind_label = ind.get("label") if isinstance(ind, dict) else None
            if ind_label:
                svc_text = (
                    f'<font size="9" color="#333333">{ind_label}</font>'
                    f'<font size="8" color="#888888"> (OSINT-Indiz)</font>'
                )
            else:
                ports = c.get("ports") or []
                if ports:
                    names = [str(port_product.get(int(p) if str(p).isdigit() else p, p))
                             for p in ports]
                    seen  = list(dict.fromkeys(names))
                    label = ", ".join(seen[:3])
                    if len(seen) > 3:
                        label += f" (+{len(seen)-3})"
                else:
                    label = c.get("service") or "—"
                svc_text = f'<font size="9" color="#333333">{label}</font>'
        except Exception:
            svc_text = f'<font size="9" color="#333333">{c.get("service") or "—"}</font>'
        svc_cell = Paragraph(svc_text, ns)

        # Exploit-Zelle: CISA KEV → rot, ExploitDB → orange, sonst grau
        exploit_cell = _exploit_cell(styles, exploit, c.get("exploitdb", False))

        # EPSS-Zelle
        epss_cell = _epss_cell(styles, c.get("epss_score"))

        rows.append([cve_cell, cvss_cell, svc_cell, exploit_cell, epss_cell])

    # "+ N weitere" Zeile
    if remaining > 0:
        rows.append([
            Paragraph(f'<font size="9" color="#AAAAAA">+ {remaining} weitere CVEs</font>', ns),
            Paragraph(f'<font size="8" color="#AAAAAA">Medium /\nNiedrig</font>', ns),
            Paragraph(f'<font size="9" color="#AAAAAA">verschiedene Dienste</font>', ns),
            Paragraph("", ns),
            Paragraph("", ns),
        ])

    # Spaltenbreiten: CVE | CVSS | Dienst | Exploit | EPSS
    col_w = [38 * mm, 18 * mm, 46 * mm, 38 * mm, 35 * mm]
    tbl = Table(rows, colWidths=col_w)
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
    for i in range(1, len(rows)):
        if i % 2 == 0:
            ts.add("BACKGROUND", (0, i), (-1, i), _C_ROW_ALT)
    tbl.setStyle(ts)
    elements.append(tbl)
    elements.append(Spacer(1, 8))


def _cvss_badge(styles: Dict, cvss: Optional[float]) -> Table:
    """Farbiges CVSS-Badge — Zahl in Farbe mit Rahmen."""
    ns = styles.get("normal") or styles.get("Normal")
    if cvss is None:
        bg, bd, tx, val = "#F4F4F4", "#AAAAAA", "#666666", "n/a"
    elif cvss >= 9.0:
        bg, bd, tx, val = "#FDECEA", "#C0392B", "#C0392B", f"{cvss}"
    elif cvss >= 7.0:
        bg, bd, tx, val = "#FEF3E8", "#E67E22", "#E67E22", f"{cvss}"
    elif cvss >= 4.0:
        bg, bd, tx, val = "#FEF9ED", "#F39C12", "#A06010", f"{cvss}"
    else:
        bg, bd, tx, val = "#F4F8F4", "#27AE60", "#27AE60", f"{cvss}"

    badge = Table(
        [[Paragraph(f'<font size="9" color="{tx}"><b>{val}</b></font>', ns)]],
        colWidths=[14 * mm],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor(bg)),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor(bd)),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    return badge


def _confidence_badge(styles: Dict, confidence: Any) -> Optional[Table]:
    """Kleines Confidence-Badge — zeigt VERIFIED / INFERRED / UNMATCHED an.

    Gibt None zurück wenn kein confidence-Wert vorhanden ist (Rückwärtskompatibilität).
    """
    try:
        from shodan_report.pdf.sections.data.cve_enricher import MatchConfidence
        if confidence is None:
            return None
        if confidence == MatchConfidence.VERIFIED:
            bg, bd, tx, label = "#ECFDF5", "#059669", "#059669", "verifiziert"
        elif confidence == MatchConfidence.INFERRED:
            bg, bd, tx, label = "#FFF7ED", "#D97706", "#D97706", "inferred"
        elif confidence == MatchConfidence.UNMATCHED:
            bg, bd, tx, label = "#F3F4F6", "#9CA3AF", "#6B7280", "unmatched"
        else:
            return None
    except Exception:
        return None

    ns = styles.get("normal") or styles.get("Normal")
    badge = Table(
        [[Paragraph(f'<font size="7" color="{tx}"><b>{label}</b></font>', ns)]],
        colWidths=[18 * mm],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor(bg)),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor(bd)),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    return badge


def _exploit_cell(styles: Dict, exploit_status: str, exploitdb: bool) -> Paragraph:
    """Exploit-Zelle: CISA KEV (rot) > ExploitDB (orange) > kein Exploit (grau)."""
    ns = styles.get("normal") or styles.get("Normal")
    is_kev = exploit_status == "public"
    if is_kev and exploitdb:
        text  = '<font size="8" color="#991b1b"><b>CISA KEV + ExploitDB</b></font>'
    elif is_kev:
        text  = '<font size="8" color="#991b1b"><b>CISA KEV</b></font>'
    elif exploitdb:
        text  = '<font size="8" color="#9a3412"><b>Exploit öffentlich</b></font>'
    else:
        text  = '<font size="8" color="#9CA3AF">—</font>'
    return Paragraph(text, ns)


def _epss_cell(styles: Dict, score: Optional[float]) -> Paragraph:
    """EPSS-Score als farbiger Prozentwert."""
    ns = styles.get("normal") or styles.get("Normal")
    if score is None:
        return Paragraph('<font size="8" color="#9CA3AF">—</font>', ns)
    pct = score * 100
    if pct >= 50:
        color = "#991b1b"
    elif pct >= 20:
        color = "#9a3412"
    elif pct >= 5:
        color = "#92400e"
    else:
        color = "#6b7280"
    return Paragraph(
        f'<font size="8" color="{color}"><b>{pct:.1f}%</b></font>',
        ns,
    )


def _relevance_badge(styles: Dict, cvss: Optional[float]) -> Table:
    """Farbiges Relevanz-Badge (kritisch/hoch/mittel/niedrig)."""
    ns = styles.get("normal") or styles.get("Normal")
    if cvss is None:
        bg, bd, tx, label = "#F4F4F4", "#AAAAAA", "#666666", "unbekannt"
    elif cvss >= 9.0:
        bg, bd, tx, label = "#FDECEA", "#C0392B", "#C0392B", "kritisch"
    elif cvss >= 7.0:
        bg, bd, tx, label = "#FEF3E8", "#E67E22", "#E67E22", "hoch"
    elif cvss >= 4.0:
        bg, bd, tx, label = "#FEF9ED", "#F39C12", "#A06010", "medium"
    else:
        bg, bd, tx, label = "#F4F8F4", "#27AE60", "#27AE60", "niedrig"

    badge = Table(
        [[Paragraph(f'<font size="9" color="{tx}"><b>{label}</b></font>', ns)]],
        colWidths=[22 * mm],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor(bg)),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor(bd)),
        ("TOPPADDING",    (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    return badge


def _final_evaluation_paragraph(elements: List, styles: Dict, cve_data: List[Dict]) -> None:
    """Grau hinterlegte Hinweis-Box am Ende — wie im Screenshot."""
    ns = styles.get("normal") or styles.get("Normal")

    total          = len(cve_data)
    crit           = len([c for c in cve_data if (c.get("cvss") or 0) >= 9.0])
    public_exploits = len([c for c in cve_data if c.get("exploit_status") == "public"])

    text = (
        "Hinweis: CVE-Zuordnungen basieren auf öffentlich sichtbaren Softwareversionen (Inferred). "
        "Keine aktive Verifikation der Ausnutzbarkeit. "
        "Empfehlung: technische Verifikation durch IT-Betrieb. "
        f"Vollständige CVE-Liste auf Anfrage verfügbar."
    )

    box = Table(
        [[Paragraph(f'<font size="8" color="#444444">{text}</font>', ns)]],
        colWidths=[175 * mm],
    )
    box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#F8F8F8")),
        ("BOX",           (0, 0), (-1, -1), 0.5, HexColor("#DDDDDD")),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(box)


def _create_unmatched_cve_note(
    elements: List, styles: Dict, cve_data_unmatched: List[Dict]
) -> None:
    """Zeigt UNMATCHED CVEs in einem eigenen transparenten Abschnitt.

    UNMATCHED bedeutet: Das Tool konnte den CVE keinem erkannten Dienst zuordnen —
    kein VENDOR_MAP-Eintrag, kein CPE-Match. Die CVEs stammen aus Shodan-Metadaten
    und sind ohne aktive Verifikation nicht bewertbar. Sie werden NICHT in den
    KPI-Counts berücksichtigt.
    """
    if not cve_data_unmatched:
        return

    ns = styles.get("normal") or styles.get("Normal")
    _C_BORDER = HexColor("#E5E7EB")
    _C_BG     = HexColor("#F9FAFB")

    elements.append(Spacer(1, 10))

    elements.append(Paragraph(
        f'<font size="9" color="#4B5563"><b>Nicht zuordenbare CVEs ({len(cve_data_unmatched)})</b></font>',
        ns,
    ))
    elements.append(Spacer(1, 4))

    note_text = (
        "Diese CVEs konnten keinem erkannten Dienst direkt zugeordnet werden. "
        "Sie basieren auf Shodan-Metadaten und sind ohne aktive Verifikation "
        "nicht bewertbar. Eine manuelle Prüfung durch den IT-Betrieb wird empfohlen."
    )
    box = Table(
        [[Paragraph(f'<font size="8" color="#6B7280">{note_text}</font>', ns)]],
        colWidths=[175 * mm],
    )
    box.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), _C_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, _C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    elements.append(box)
    elements.append(Spacer(1, 5))

    for c in sorted(cve_data_unmatched, key=lambda x: (x.get("cvss") or 0), reverse=True):
        cid      = c.get("id") or "—"
        cvss     = c.get("cvss")
        note     = c.get("match_note") or "Kein Mapping möglich"
        nvd_url  = c.get("nvd_url") or f"https://nvd.nist.gov/vuln/detail/{cid}"
        cvss_str = f"CVSS {cvss}" if cvss is not None else "CVSS unbekannt"
        line = (
            f'<a href="{nvd_url}"><font size="8" color="#6B7280">{cid}</font></a>'
            f'<font size="8" color="#9CA3AF">  {cvss_str} — {note}</font>'
        )
        elements.append(Paragraph(line, ns))

    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        '<font size="7" color="#D1D5DB">confidence: unmatched · nicht in KPI-Zählung</font>',
        ns,
    ))


# BUGFIX: Bug 2 — Separater Abschnitt für CVEs mit low_confidence-Flag
# (vulnerable:false Plattformabhängigkeiten, z.B. Apache als Hosting-Plattform
# für eine betroffene Webanwendung, nicht als direkt verwundbare Komponente).
def _create_low_confidence_cve_note(
    elements: List, styles: Dict, cve_data_low: List[Dict]
) -> None:
    """Zeigt low_confidence CVEs in einem gesonderten Info-Abschnitt.

    Diese CVEs sind in NVD mit vulnerable:false für die gescannte Komponente
    eingetragen — sie betreffen eine andere Komponente, die auf dem System läuft.
    Sie werden NICHT in der KPI-Zählung berücksichtigt.

    BUGFIX: Bug 2 — Plausibilitätsfilter-Ergebnis darstellen.
    """
    if not cve_data_low:
        return

    ns = styles.get("normal") or styles.get("Normal")
    _C_BORDER = HexColor("#DDDDDD")
    _C_BG     = HexColor("#FFFBEB")   # leicht gelblicher Hintergrund für Hinweis

    elements.append(Spacer(1, 10))

    # Überschrift
    elements.append(Paragraph(
        '<font size="9" color="#B45309"><b>Hinweis: Weitere CVEs mit geringer Relevanz '
        f'({len(cve_data_low)})</b></font>',
        ns,
    ))
    elements.append(Spacer(1, 4))

    # Erklärungstext
    note_text = (
        "Die folgenden CVEs wurden per CPE-Matching gefunden, betreffen die gescannte Komponente "
        "jedoch nur als Laufzeitplattform (NVD: vulnerable:false). "
        "Sie sind möglicherweise nicht direkt ausnutzbar und werden in den KPI-Zählungen "
        "<b>nicht</b> berücksichtigt. Manuelle Prüfung empfohlen."
    )
    elements.append(Paragraph(
        f'<font size="8" color="#78350F">{note_text}</font>', ns
    ))
    elements.append(Spacer(1, 6))

    # Kompakte Listendarstellung
    for c in sorted(cve_data_low, key=lambda x: (x.get("cvss") or 0), reverse=True):
        cid    = c.get("id") or "—"
        cvss   = c.get("cvss")
        reason = c.get("low_confidence_reason") or "Plattformabhängigkeit (vulnerable:false)"
        nvd_url = c.get("nvd_url") or f"https://nvd.nist.gov/vuln/detail/{cid}"
        cvss_str = f"CVSS {cvss}" if cvss is not None else "CVSS unbekannt"
        line = (
            f'<a href="{nvd_url}"><font size="8" color="#2563A8">{cid}</font></a>'
            f'<font size="8" color="#666666">  {cvss_str} — {reason}</font>'
        )
        elements.append(Paragraph(line, ns))

    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        '<font size="7" color="#AAAAAA">'
        'Quelle: NVD CPE vulnerable-Flag · automatisch klassifiziert'
        '</font>',
        ns,
    ))