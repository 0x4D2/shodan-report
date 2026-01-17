"""
CVE- & Exploit-Übersicht für PDF-Reports - KOMPAKTE VERSION für One-Page Design.
"""

import re
from typing import List, Dict, Any, Optional
from reportlab.platypus import Spacer, Paragraph, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.colors import HexColor
from shodan_report.pdf.layout import keep_section, set_table_repeat, set_table_no_split
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
    context: Optional[Any] = None,
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
    heading_style = styles.get("heading1", styles.get("heading2"))
    elements.append(keep_section([Paragraph("5. CVE-ÜBERSICHT", heading_style), Spacer(1, 8)]))

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

    # 2. DETAILED CVE TABLE (per-service) — default: Top-N, full list only if requested
    show_full = False
    limit = 6
    try:
        if context is not None:
            show_full = bool(getattr(context, "show_full_cve_list", False))
            limit = int(getattr(context, "cve_limit", 10) or 10)
    except Exception:
        show_full = False
        limit = 10

    _create_detailed_cve_table(elements, styles, cve_data, technical_json, show_full=show_full, limit=limit)
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
            cve_data.append({
                "id": cid,
                "cvss": cvss_val,
                "ports": ports,
                "service": service[:40],
                "summary": ent.get("summary") or "",
                "exploit_status": ent.get("exploit_status", "unknown"),
            })
        except Exception:
            continue

    return cve_data


def _create_risk_overview(elements: List, styles: Dict, cve_data: List[Dict]) -> None:
    """Erstelle kompakte Risiko-Übersicht mit farbigen Boxen."""

    # Zähle CVEs nach Risiko-Level
    # Count by CVSS buckets; ignore unknown (None) scores for bucket assignment
    critical = [c for c in cve_data if (c.get("cvss") is not None and c.get("cvss") >= 9.0)]
    high = [c for c in cve_data if (c.get("cvss") is not None and 7.0 <= c.get("cvss") < 9.0)]
    medium = [c for c in cve_data if (c.get("cvss") is not None and 4.0 <= c.get("cvss") < 7.0)]
    low = [c for c in cve_data if (c.get("cvss") is not None and c.get("cvss") < 4.0)]

    # Farbdefinitionen
    color_critical = colors.HexColor("#dc2626")  # Rot
    color_high = colors.HexColor("#f97316")  # Orange
    color_medium = colors.HexColor("#eab308")  # Gelb
    color_low = colors.HexColor("#16a34a")  # Grün
    color_unknown = colors.HexColor("#585758DC")  # Grau

    # Kompakte Tabelle für Risiko-Boxen (inkl. 'UNBEKANNT' für CVEs ohne CVSS)
    unknown = len([c for c in cve_data if c.get("cvss") is None])
    table_data = [
        [
            _create_risk_cell("KRITISCH", len(critical), color_critical),
            _create_risk_cell("HOCH", len(high), color_high),
            _create_risk_cell("MEDIUM", len(medium), color_medium),
            _create_risk_cell("NIEDRIG", len(low), color_low),
            _create_risk_cell("UNBEKANNT", unknown, color_unknown),
        ]
    ]

    # Kleinere Boxen für kompaktere Layouts: 5 * 20mm = 100mm total.
    # Bessere Option für enge oder zweiseitige Layouts.
    table = Table(table_data, colWidths=[20 * mm, 20 * mm, 20 * mm, 20 * mm, 20 * mm])
    set_table_no_split(table)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), color_critical),
                ("BACKGROUND", (1, 0), (1, 0), color_high),
                ("BACKGROUND", (2, 0), (2, 0), color_medium),
                ("BACKGROUND", (3, 0), (3, 0), color_low),
                ("BACKGROUND", (4, 0), (4, 0), color_unknown),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGNMENT", (0, 0), (-1, 0), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                # Removed table-level FONTSIZE to allow inline Paragraph font tags to take effect.
                ("PADDING", (0, 0), (-1, 0), (6, 4)),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ]
        )
    )

    elements.append(table)
    elements.append(Spacer(1, 6))


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


def _create_detailed_cve_table(elements: List, styles: Dict, cve_data: List[Dict], technical_json: Dict[str, Any], *, show_full: bool = False, limit: int = 10) -> None:
    """Erstelle eine detaillierte per-service CVE-Tabelle mit Spalten:
    Dienst | CVE | CVSS | Exploit-Status | Relevanz
    """
    if not cve_data:
        return

    # Build port -> product map for nicer service names. Prefer `services` entries.
    port_product = {}
    services_src = None
    if isinstance(technical_json, dict):
        services_src = technical_json.get("services") or technical_json.get("open_ports") or []
    else:
        services_src = getattr(technical_json, "services", None) or getattr(technical_json, "open_ports", []) or []

    for s in (services_src or []):
        try:
            if isinstance(s, dict):
                p = s.get("port")
                # attempt to get a friendly product/service name
                prod = None
                if isinstance(s.get("service"), dict):
                    prod = s.get("service", {}).get("product") or s.get("service", {}).get("name")
                prod = prod or s.get("product") or s.get("service") or s.get("name")
            else:
                p = getattr(s, "port", None)
                prod = getattr(s, "product", None) or getattr(s, "service", None) or str(p)

            # normalize product label
            if isinstance(prod, dict):
                prod = prod.get("product") or prod.get("name") or str(p)
            label = str(prod).strip() if prod is not None else str(p)
            # fallback to port number label
            port_product[p] = label or str(p)
        except Exception:
            continue

    # Header
    elements.append(Spacer(1, 6))
    elements.append(keep_section([Paragraph("Detaillierte CVE-Übersicht", styles.get("heading3", styles.get("heading2"))), Spacer(1, 8)]))
    elements.append(Spacer(1, 2))

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

    def relevance_from_cvss(cvss: Optional[float]) -> str:
        try:
            if cvss is None:
                return "unbekannt"
            if cvss >= 9.0:
                return "kritisch"
            if cvss >= 7.0:
                return "hoch"
            if cvss >= 4.0:
                return "mittel"
            return "niedrig"
        except Exception:
            return "unbekannt"

    # Decide which CVEs to show: Top-N unless show_full is True
    def _sort_key_all(x):
        v = x.get("cvss")
        return v if v is not None else -1

    sorted_all = sorted(cve_data, key=_sort_key_all, reverse=True)
    if show_full:
        to_display = sorted_all
    else:
        to_display = sorted_all[: max(0, int(limit or 10))]

    # Each cve_data entry may correspond to ports (list) or service string
    for c in to_display:
        cid = c.get("id")
        cvss = c.get("cvss") if c.get("cvss") is not None else None
        serv = c.get("service") or ""
        # Prefer mapped product names for ports; if many, show short summary
        try:
            ports = c.get("ports", []) or []
            if ports:
                names = []
                for p in ports:
                    # ports may be strings or ints
                    key = p
                    try:
                        key = int(p)
                    except Exception:
                        key = p
                    names.append(str(port_product.get(key, port_product.get(p, p))))

                # Deduplicate while preserving order
                seen = set()
                dedup_names = []
                for n in names:
                    if n not in seen:
                        seen.add(n)
                        dedup_names.append(n)

                if len(dedup_names) > 3:
                    service_label = ", ".join(dedup_names[:2]) + f" (+{len(dedup_names)-2})"
                else:
                    service_label = ", ".join(dedup_names)
            else:
                # fallback to the generic service string (often 'Various' or empty)
                service_label = serv or "-"
        except Exception:
            service_label = serv or "-"

        exploit_status = map_exploit(c.get("exploit_status", c.get("exploit", "unknown")))
        rel = relevance_from_cvss(cvss)

        table_data.append([
            Paragraph(str(service_label), styles["normal"]),
            Paragraph(str(cid), styles["normal"]),
            Paragraph(f"{cvss if cvss is not None else 'n/a'}", styles["normal"]),
            Paragraph(exploit_status, styles["normal"]),
            Paragraph(rel, styles["normal"]),
        ])

    # Use technical section styling for consistency
    col_widths = [25 * mm, 45 * mm, 20 * mm, 40 * mm, 30 * mm]
    table = Table(table_data, colWidths=col_widths)
    set_table_repeat(table, 1)
    set_table_no_split(table)
    border_color = HexColor("#e5e7eb")
    header_bg = HexColor("#f8fafc")
    table_style = TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, border_color),
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#111827")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ])

    # Add per-row CVSS accent backgrounds like the compact table
    # Only iterate over the rows that are actually displayed to avoid
    # adding background commands for non-existent rows (which can
    # occur when `show_full` is False and we truncated the list).
    for i, c in enumerate(to_display, start=1):
        try:
            cvss = c.get("cvss")
            if cvss is None:
                continue
            if cvss >= 9.0:
                table_style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fee2e2"))
            elif cvss >= 7.0:
                table_style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#ffedd5"))
            elif cvss >= 4.0:
                table_style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fef9c3"))
        except Exception:
            # Defensive: skip styling for this row on any error
            continue

    table.setStyle(table_style)
    elements.append(table)
    elements.append(Spacer(1, 6))

    # If we truncated the list, add a short note referencing the sidecar containing the full list
    try:
        total = len(cve_data)
        shown = len(to_display)
        if shown < total:
            elements.append(
                Paragraph(
                    f"<i>Es werden die {shown} wichtigsten CVEs angezeigt; {total - shown} weitere CVEs liegen in der Begleitdatei (.mdata.json) neben dem PDF vor.</i>",
                    ParagraphStyle(
                        "SmallItalic",
                        parent=styles["normal"],
                        fontSize=8,
                        textColor=colors.HexColor("#6b7280"),
                    ),
                )
            )
    except Exception:
        pass


def _final_evaluation_paragraph(elements: List, styles: Dict, cve_data: List[Dict]) -> None:
    total = len(cve_data)
    high = len([c for c in cve_data if (c.get("cvss") is not None and c.get("cvss") >= 9.0)])
    public_exploits = len([c for c in cve_data if c.get("exploit_status") == "public"])

    eval_text = (
        "Bewertung:<br/>"
        f"Keine aktuell aktiv ausgenutzten Schwachstellen mit kritischer Priorität identifiziert.<br/>"
        f"Insgesamt identifizierte CVEs: {total}. Kritisch (CVSS≥9): {high}. Öffentliche Exploits: {public_exploits}."
    )
    elements.append(Paragraph(eval_text, styles["normal"]))
