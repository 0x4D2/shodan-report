"""
CVE- & Exploit-Übersicht für PDF-Reports - KOMPAKTE VERSION für One-Page Design.
"""

import re
from typing import List, Dict, Any, Optional
from reportlab.platypus import Spacer, Paragraph, Table, TableStyle, KeepTogether
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from ..sections.data.cve_enricher import enrich_cves


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
) -> None:
    """
    Erstelle KOMPAKTE CVE-Übersicht Section für One-Page Design.

    Args:
        elements: Liste der PDF-Elemente
        styles: Dictionary mit PDF-Styles
        technical_json: Technische Daten mit CVEs
        evaluation: Optional - Evaluation Ergebnisse
    """
    # Weniger Abstand für kompaktes Design
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("5. CVE-ÜBERSICHT", _get_style(styles, "heading1", "heading2")))
    elements.append(Spacer(1, 4))

    # Extrahiere CVE-Daten
    cve_data = _extract_cve_data(technical_json)

    if not cve_data:
        # Minimal "Keine CVEs" Darstellung
        elements.append(
            Paragraph("✓ Keine kritischen CVEs identifiziert", styles["normal"])
        )
        return

    # 1. RISIKO-ÜBERSICHT (kompakte farbige Boxen)
    _create_risk_overview(elements, styles, cve_data)

    # 2. DETAILED CVE TABLE (per-service) ersetzt die alte kompakte Tabelle und Indicator
    _create_detailed_cve_table(elements, styles, cve_data, technical_json)
    _final_evaluation_paragraph(elements, styles, cve_data)


def _extract_cve_data(technical_json: Dict[str, Any]) -> List[Dict]:
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
        services = technical_json.get("open_ports") or technical_json.get("services") or []
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
    enriched = enrich_cves(unique_ids, technical_json, lookup_nvd=False)

    cve_data = []
    for ent in enriched:
        try:
            cid = ent.get("id")
            cvss = ent.get("cvss") if ent.get("cvss") is not None else 0
            ports = ent.get("ports", []) or []
            service = ",".join([str(p) for p in ports]) if ports else "Various"
            cve_data.append({
                "id": cid,
                "cvss": float(cvss) if cvss is not None else 0,
                "service": service[:20],
                "summary": ent.get("summary") or "",
                "exploit_status": ent.get("exploit_status", "unknown"),
            })
        except Exception:
            continue

    return cve_data


def _create_risk_overview(elements: List, styles: Dict, cve_data: List[Dict]) -> None:
    """Erstelle kompakte Risiko-Übersicht mit farbigen Boxen."""

    # Zähle CVEs nach Risiko-Level
    critical = [c for c in cve_data if c.get("cvss", 0) >= 9.0]
    high = [c for c in cve_data if 7.0 <= c.get("cvss", 0) < 9.0]
    medium = [c for c in cve_data if 4.0 <= c.get("cvss", 0) < 7.0]
    low = [c for c in cve_data if c.get("cvss", 0) < 4.0]

    # Farbdefinitionen
    color_critical = colors.HexColor("#dc2626")  # Rot
    color_high = colors.HexColor("#f97316")  # Orange
    color_medium = colors.HexColor("#eab308")  # Gelb
    color_low = colors.HexColor("#16a34a")  # Grün

    # Kompakte Tabelle für Risiko-Boxen
    table_data = [
        [
            _create_risk_cell("KRITISCH", len(critical), color_critical),
            _create_risk_cell("HOCH", len(high), color_high),
            _create_risk_cell("MEDIUM", len(medium), color_medium),
            _create_risk_cell("NIEDRIG", len(low), color_low),
        ]
    ]

    table = Table(table_data, colWidths=[45, 45, 45, 45])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), color_critical),
                ("BACKGROUND", (1, 0), (1, 0), color_high),
                ("BACKGROUND", (2, 0), (2, 0), color_medium),
                ("BACKGROUND", (3, 0), (3, 0), color_low),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGNMENT", (0, 0), (-1, 0), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("PADDING", (0, 0), (-1, 0), (6, 4)),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )

    elements.append(table)
    elements.append(Spacer(1, 6))


def _create_risk_cell(label: str, count: int, color) -> Paragraph:
    """Erstelle eine Risiko-Zelle für die Übersicht."""
    text = f"<b>{label}<br/>{count}</b>"
    return Paragraph(
        text,
        style=ParagraphStyle(
            "RiskCell",
            alignment=1,  # Center
            textColor=colors.white,
            fontSize=9,
            leading=11,
            spaceBefore=0,
            spaceAfter=0,
        ),
    )


def _create_compact_cve_table(
    elements: List, styles: Dict, cve_data: List[Dict]
) -> None:
    """Erstelle kompakte CVE-Tabelle mit Farbcodierung."""

    # Sortiere nach CVSS (höchste zuerst) und nehme nur Top 8
    sorted_cves = sorted(cve_data, key=lambda x: x.get("cvss", 0), reverse=True)[:8]

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
        cvss = cve.get("cvss", 0)

        # Bestimme Farbe basierend auf CVSS
        if cvss >= 9.0:
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
                    f"<font color='{text_color.hexval()}'><b>{cvss}</b></font>",
                    styles["normal"],
                ),
                Paragraph(
                    f"<font color='{text_color.hexval()}'>{cve['service']}</font>",
                    styles["normal"],
                ),
                Paragraph(exploit_icon, styles["normal"]),
            ]
        )

    # Tabelle erstellen (sehr schmale Spalten)
    col_widths = [40, 20, 35, 15]  # mm statt Punkte für bessere Kontrolle

    table = Table(table_data, colWidths=col_widths, repeatRows=1)

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
            ("PADDING", (0, 0), (-1, -1), (2, 1)),  # Minimal padding
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
        cvss = cve.get("cvss", 0)
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
    if total_cves > 8:
        elements.append(
            Paragraph(
                f"<i>... und {total_cves - 8} weitere CVEs</i>",
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


def _create_detailed_cve_table(elements: List, styles: Dict, cve_data: List[Dict], technical_json: Dict[str, Any]) -> None:
    """Erstelle eine detaillierte per-service CVE-Tabelle mit Spalten:
    Dienst | CVE | CVSS | Exploit-Status | Relevanz
    """
    if not cve_data:
        return

    # Build port -> product map for nicer service names
    port_product = {}
    if isinstance(technical_json, dict):
        for s in technical_json.get("open_ports") or technical_json.get("services") or []:
            try:
                p = s.get("port") if isinstance(s, dict) else getattr(s, "port", None)
                prod = None
                if isinstance(s, dict):
                    prod = (s.get("service") or s.get("product") or {}).get("product") if isinstance(s.get("service") or s.get("product"), dict) else (s.get("service") or s.get("product") or "")
                else:
                    prod = getattr(s, "product", "")
                port_product[p] = prod or str(p)
            except Exception:
                continue

    # Header
    elements.append(Spacer(1, 6))
    elements.append(Paragraph("Detaillierte CVE-Übersicht", _get_style(styles, "heading3", "heading2")))
    elements.append(Spacer(1, 4))

    table_data = [[
        Paragraph("<b>Dienst</b>", styles["normal"]),
        Paragraph("<b>CVE</b>", styles["normal"]),
        Paragraph("<b>CVSS</b>", styles["normal"]),
        Paragraph("<b>Exploit-Status</b>", styles["normal"]),
        Paragraph("<b>Relevanz</b>", styles["normal"]),
    ]]

    def map_exploit(status: str) -> str:
        return {
            "public": "öffentlich bekannt",
            "private": "teilweise",
            "none": "nicht bekannt",
            "unknown": "unbekannt",
        }.get(status, str(status) if status else "unbekannt")

    def relevance_from_cvss(cvss: float) -> str:
        try:
            if cvss >= 9.0:
                return "kritisch"
            if cvss >= 7.0:
                return "hoch"
            if cvss >= 4.0:
                return "mittel"
            return "niedrig"
        except Exception:
            return "unbekannt"

    # Each cve_data entry may correspond to ports (list) or service string
    for c in sorted(cve_data, key=lambda x: x.get("cvss", 0), reverse=True):
        cid = c.get("id")
        cvss = c.get("cvss", 0) or 0
        serv = c.get("service") or ""
        # if service is list of ports, map to product names
        if isinstance(serv, str) and "," in serv:
            # keep as-is
            service_label = serv
        else:
            # attempt to map numeric port
            try:
                ports = c.get("ports", []) or []
                if ports:
                    names = [str(port_product.get(p, p)) for p in ports]
                    service_label = ",".join(names)
                else:
                    service_label = serv or "-"
            except Exception:
                service_label = serv or "-"

        exploit_status = map_exploit(c.get("exploit_status", c.get("exploit", "unknown")))
        rel = relevance_from_cvss(float(cvss) if cvss is not None else 0)

        table_data.append([
            Paragraph(str(service_label), styles["normal"]),
            Paragraph(str(cid), styles["normal"]),
            Paragraph(f"{cvss}", styles["normal"]),
            Paragraph(exploit_status, styles["normal"]),
            Paragraph(rel, styles["normal"]),
        ])

    col_widths = [60, 70, 30, 80, 50]
    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    # Modern table styling similar to compact view
    table_style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("PADDING", (0, 0), (-1, -1), (4, 3)),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ("ALIGNMENT", (2, 1), (2, -1), "CENTER"),
    ])

    # Add per-row CVSS accent backgrounds like the compact table
    for i, c in enumerate(sorted(cve_data, key=lambda x: x.get("cvss", 0), reverse=True), start=1):
        cvss = c.get("cvss", 0) or 0
        if cvss >= 9.0:
            table_style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fee2e2"))
        elif cvss >= 7.0:
            table_style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#ffedd5"))
        elif cvss >= 4.0:
            table_style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fef9c3"))

    table.setStyle(table_style)

    elements.append(table)
    elements.append(Spacer(1, 6))


def _final_evaluation_paragraph(elements: List, styles: Dict, cve_data: List[Dict]) -> None:
    total = len(cve_data)
    high = len([c for c in cve_data if (c.get("cvss") or 0) >= 9.0])
    public_exploits = len([c for c in cve_data if c.get("exploit_status") == "public"])

    eval_text = (
        "Bewertung:<br/>"
        f"Keine aktuell aktiv ausgenutzten Schwachstellen mit kritischer Priorität identifiziert.<br/>"
        f"Insgesamt identifizierte CVEs: {total}. Kritisch (CVSS≥9): {high}. Öffentliche Exploits: {public_exploits}."
    )
    elements.append(Paragraph(eval_text, styles["normal"]))
