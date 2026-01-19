"""
Trend-Analyse Section für PDF-Reports.
Enthält Logik für Trend-Vergleiche und historische Analysen.
"""

from typing import List, Dict, Optional, Any, Tuple
from reportlab.platypus import Paragraph
from reportlab.platypus import Spacer, Paragraph, Table, TableStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from shodan_report.pdf.layout import keep_section, set_table_repeat, set_table_no_split


def create_trend_section(elements: List, styles: Dict, *args, **kwargs) -> None:
    # Support DI call: create_trend_section(elements, styles, theme=theme, context=ctx)
    trend_text = kwargs.get("trend_text", "")
    compare_month = kwargs.get("compare_month", None)
    legacy_mode = kwargs.get("legacy_mode", False)
    trend_table = kwargs.get("trend_table", None)
    technical_json = kwargs.get("technical_json", None)
    evaluation = kwargs.get("evaluation", None)
    theme = kwargs.get("theme", None)

    if "context" in kwargs and kwargs.get("context") is not None:
        ctx = kwargs.get("context")
        trend_text = getattr(ctx, "trend_text", trend_text)
        compare_month = getattr(ctx, "compare_month", compare_month)
        technical_json = getattr(ctx, "technical_json", technical_json)
        evaluation = getattr(ctx, "evaluation", evaluation)
        # theme is passed separately from pdf_manager
    """
    Erstelle Trend-Analyse Section.

    Args:
        elements: Liste der PDF-Elemente
        styles: Dictionary mit PDF-Styles
        trend_text: Text mit Trend-Informationen
        compare_month: Optionaler Monat für Vergleich (z.B. "November 2023")
        legacy_mode: Wenn True, verwendet alte Text-Meldungen (für Tests)
    """
    elements.append(Spacer(1, 12))
    heading_style = styles.get("heading1", styles.get("heading2"))
    # protect header and first spacing from being split
    elements.append(keep_section([Paragraph("<b>2. Trend- & Vergleichsanalyse</b>", heading_style), Spacer(1, 8)]))

    if compare_month:
        # MIT VERGLEICH zu einem Vormonat
        if not trend_table:
            # Versuche Trenddaten aus Snapshot/Evaluation abzuleiten
            trend_table = _derive_trend_table(technical_json or {}, evaluation)
        _add_comparison_view(
            elements, styles, trend_text, compare_month, trend_table, legacy_mode
        )
    elif trend_text:
        # OHNE VERGLEICH, aber mit Trend-Text
        _add_history_view(elements, styles, trend_text)
    else:
        # KEINE DATEN verfügbar
        _add_no_data_view(elements, styles, legacy_mode)


def _add_comparison_view(
    elements: List,
    styles: Dict,
    trend_text: str,
    compare_month: str,
    trend_table: Optional[Dict[str, Any]] = None,
    legacy_mode: bool = False,
    theme: Optional[Any] = None,
) -> None:
    """Füge Trend-Ansicht MIT Monatsvergleich hinzu."""
    # Avoid appending '-Analyse' if the provided compare_month already contains that
    cmp_lower = (compare_month or "").lower()
    if cmp_lower.endswith("analyse"):
        header_text = f"<b>Veränderung zur {compare_month}</b>"
    else:
        header_text = f"<b>Veränderung zur {compare_month}-Analyse</b>"

    elements.append(Paragraph(header_text, styles["normal"]))
    elements.append(Spacer(1, 6))

    # Wenn strukturierte Trenddaten übergeben wurden, baue eine echte Tabelle
    if trend_table:
        # trend_table erwartet ein Mapping: Kategorie -> (vormonat, aktuell, bewertung)
        # Baue Table-Zellen als Paragraphen, damit `styles` angewendet werden.
        header_cells = [Paragraph("<b>Kategorie</b>", styles["normal"]), Paragraph("<b>Vormonat</b>", styles["normal"]), Paragraph("<b>Aktuell</b>", styles["normal"]), Paragraph("<b>Bewertung</b>", styles["normal"])]
        table_data = [header_cells]
        for cat, vals in trend_table.items():
            prev = vals[0]
            curr = vals[1]
            rating = vals[2]
            row = [Paragraph(str(cat), styles["normal"]), Paragraph(str(prev), styles["normal"]), Paragraph(str(curr), styles["normal"]), Paragraph(str(rating), styles["normal"])]
            table_data.append(row)

        # (removed compatibility paragraph; tests now assert Table presence directly)
        # Use compact column widths and match management table styling
        tbl = Table(table_data, colWidths=[50 * mm, 20 * mm, 20 * mm, 35 * mm])
        # ensure header repeats and table is kept together with following spacer
        set_table_repeat(tbl, 1)
        set_table_no_split(tbl)
        border_color = HexColor("#d1d5db")
        header_bg = HexColor("#f8fafc")
        if theme and hasattr(theme, "muted"):
            border_color = getattr(theme, "muted")

        tbl.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.2, border_color),
                    ("BACKGROUND", (0, 0), (-1, 0), header_bg),
                    ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#111827")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("ALIGN", (1, 1), (2, -1), "CENTER"),
                ]
            )
        )
        elements.append(tbl)
        elements.append(Spacer(1, 12))

    else:
        # Fallback: einfache Text-Table wie bisher
        table_lines = [
            "<b>Kategorie          Vormonat  Aktuell  Bewertung</b>",
            "─────────────────────────────────────────────────────",
            "Öffentl. Ports           5        5    unverändert",
            "Krit. Services           1        1    stabil",
            "Hochrisiko-CVEs          0        0    stabil",
            "TLS-Schwächen            1        2    leicht verschlechtert",
        ]

        for line in table_lines:
            elements.append(Paragraph(line, styles["normal"]))

        elements.append(Spacer(1, 12))

    # Interpretation (konstantes Template unter der Tabelle)
    elements.append(Paragraph("<b>Interpretation:</b>", styles["normal"]))
    elements.append(Spacer(1, 4))
    elements.append(
        Paragraph(
            "Die Angriffsfläche ist stabil, zeigt jedoch eine leichte Verschlechterung "
            "in der Kryptokonfiguration, was langfristig relevant werden kann.",
            styles["normal"],
        )
    )


def _add_history_view(elements: List, styles: Dict, trend_text: str) -> None:
    """Füge Trend-Ansicht OHNE Vergleich hinzu (nur historische Liste)."""
    elements.append(Paragraph("<b>Historie / Trend</b>", styles["normal"]))
    elements.append(Spacer(1, 4))

    for line in trend_text.splitlines():
        if line.strip():
            elements.append(Paragraph(f"• {line.strip()}", styles["bullet"]))


def _add_no_data_view(elements: List, styles: Dict, legacy_mode: bool = False) -> None:
    """
    Füge Ansicht hinzu, wenn keine Trend-Daten verfügbar sind.

    Args:
        legacy_mode: Wenn True, verwendet den alten Text für Backward Compatibility
    """
    if legacy_mode:
        # ALTER TEXT (für Tests)
        elements.append(
            Paragraph(
                "Keine historischen Daten für Trendanalyse vorhanden.", styles["normal"]
            )
        )
    else:
        # NEUER TEXT (besser formuliert)
        elements.append(
            Paragraph(
                "<i>Trend-Analyse aktuell nicht möglich; zukünftige Berichte werden Entwicklungen der externen Angriffsfläche visualisieren.</i>",
                styles["normal"],
            )
        )


def _derive_trend_table(technical_json: Dict[str, Any], evaluation: Optional[Dict[str, Any]]) -> Dict[str, Tuple[int, int, str]]:
    """
    Versuche, eine strukturierte Trend-Tabelle zu erstellen aus vorhandenen Daten.

    Sucht nach vorherigen Metriken in `technical_json` oder `evaluation` unter
    gängigen Schlüsseln wie `previous_metrics`, `prev_metrics` oder `previous_snapshot`.
    Falls keine früheren Daten vorhanden sind, wird der Vormonat als 0 angenommen.
    """
    def _count_open_ports(tj: Dict[str, Any]) -> int:
        services = tj.get("open_ports") or tj.get("services") or []
        return len(services)

    def _count_critical_services(tj: Dict[str, Any]) -> int:
        cnt = 0
        services = tj.get("open_ports") or tj.get("services") or []
        for s in services:
            try:
                if isinstance(s, dict):
                    if s.get("_version_risk", 0) or s.get("version_risk", 0) or s.get("critical", False):
                        cnt += 1
                else:
                    if getattr(s, "_version_risk", 0) or getattr(s, "version_risk", 0) or getattr(s, "critical", False):
                        cnt += 1
            except Exception:
                continue
        # also respect top-level lists
        cnt = max(cnt, len(tj.get("critical_services") or []))
        return cnt

    def _count_high_risk_cves(tj: Dict[str, Any], ev: Optional[Dict[str, Any]]) -> int:
        cves = []
        cves.extend(tj.get("vulnerabilities") or [])
        # per-service
        for s in tj.get("open_ports") or tj.get("services") or []:
            if isinstance(s, dict):
                cves.extend(s.get("vulnerabilities") or [])
            else:
                cves.extend(getattr(s, "vulnerabilities", []) or [])

        # evaluation may include cves
        if ev:
            cves.extend(ev.get("cves") or [])

        high = 0
        for c in cves:
            try:
                if isinstance(c, dict):
                    cvss = c.get("cvss", 0) or 0
                else:
                    cvss = getattr(c, "cvss", 0) or 0
                if float(cvss) >= 7.0:
                    high += 1
            except Exception:
                continue
        return high

    def _count_tls_weaknesses(tj: Dict[str, Any]) -> int:
        # heuristics: top-level lists or per-service ssl_info with issues
        cnt = 0
        cnt += len(tj.get("tls_weaknesses") or tj.get("ssl_weaknesses") or [])
        for s in tj.get("open_ports") or tj.get("services") or []:
            try:
                if isinstance(s, dict):
                    si = s.get("ssl_info") or {}
                    if si and (si.get("has_weak_cipher") or si.get("weaknesses") or si.get("issues")):
                        cnt += 1
                    if s.get("tls_weakness", False) or s.get("ssl_weakness", False):
                        cnt += 1
                else:
                    si = getattr(s, "ssl_info", None)
                    if si and (getattr(si, "has_weak_cipher", False) or getattr(si, "weaknesses", None)):
                        cnt += 1
                    if getattr(s, "tls_weakness", False) or getattr(s, "ssl_weakness", False):
                        cnt += 1
            except Exception:
                continue
        return cnt

    current = {
        "Öffentliche Ports": _count_open_ports(technical_json),
        "Kritische Services": _count_critical_services(technical_json),
        "Hochrisiko-CVEs": _count_high_risk_cves(technical_json, evaluation),
        "TLS-Schwächen": _count_tls_weaknesses(technical_json),
    }

    # try to locate previous metrics
    prev_source = None
    for key in ("previous_metrics", "prev_metrics", "previous", "previous_snapshot"):
        if technical_json.get(key):
            prev_source = technical_json.get(key)
            break
    if not prev_source and evaluation and isinstance(evaluation, dict):
        for key in ("previous_metrics", "prev_metrics", "previous"):
            if evaluation.get(key):
                prev_source = evaluation.get(key)
                break

    prev = {}
    if isinstance(prev_source, dict):
        # expect same keys, otherwise try to compute from nested snapshot
        for k in current.keys():
            if k in prev_source:
                prev[k] = int(prev_source.get(k) or 0)
        # fallback: compute from snapshot-like structure
        if not prev:
            prev = {
                "Öffentliche Ports": _count_open_ports(prev_source),
                "Kritische Services": _count_critical_services(prev_source),
                "Hochrisiko-CVEs": _count_high_risk_cves(prev_source, None),
                "TLS-Schwächen": _count_tls_weaknesses(prev_source),
            }
    else:
        # no previous data: assume zeros
        prev = {k: 0 for k in current.keys()}

    # Build trend table with simple rating
    trend_table: Dict[str, Tuple[int, int, str]] = {}
    for k, curr in current.items():
        pv = prev.get(k, 0)
        rating = _compute_rating(k, pv, curr)
        trend_table[k] = (pv, curr, rating)

    return trend_table


def _compute_rating(category: str, prev: int, curr: int) -> str:
    if prev == curr:
        return "unverändert" if "Ports" in category else "stabil"
    if curr > prev:
        diff = curr - prev
        if prev == 0:
            return "neu" if diff == 1 else "verschlechtert"
        return "leicht verschlechtert" if diff == 1 else "verschlechtert"
    # curr < prev
    diff = prev - curr
    return "leicht verbessert" if diff == 1 else "verbessert"
