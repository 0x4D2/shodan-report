"""
Trend-Analyse Section für PDF-Reports.
Vergleicht aktuelle Messung mit Vormonat und kommuniziert
Veränderungen klar und management-tauglich.
"""

from typing import List, Dict, Optional, Any, Tuple
from reportlab.platypus import Spacer, Paragraph, Table, TableStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.graphics.shapes import Drawing, Line, Circle, String, Rect
from shodan_report.pdf.layout import keep_section, set_table_repeat, set_table_no_split


# ─────────────────────────────────────────────────────────────────────────────
# HAUPTFUNKTION
# ─────────────────────────────────────────────────────────────────────────────

def create_trend_section(elements: List, styles: Dict, *args, **kwargs) -> None:
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

    elements.append(Spacer(1, 12))
    heading_style = styles.get("heading1", styles.get("heading2"))
    elements.append(keep_section([
        Paragraph("<b>5. Trend- & Vergleichsanalyse</b>", heading_style),
        Spacer(1, 8)
    ]))

    if compare_month:
        if not trend_table:
            trend_table = _derive_trend_table(technical_json or {}, evaluation)
        # Guard: if all previous values are 0 there is no real prior snapshot —
        # show the first-report baseline view instead of a misleading 0→N table.
        prev_all_zero = trend_table and all(pv == 0 for pv, _cv, _r in trend_table.values())
        if prev_all_zero:
            _add_no_data_view(elements, styles, legacy_mode, technical_json, evaluation)
        else:
            _add_comparison_view(
                elements, styles, trend_text, compare_month,
                trend_table, legacy_mode, theme, technical_json, evaluation,
            )
    elif trend_text:
        _add_history_view(elements, styles, trend_text)
    else:
        _add_no_data_view(elements, styles, legacy_mode, technical_json, evaluation)


# ─────────────────────────────────────────────────────────────────────────────
# KEIN VERGLEICHSMONAT — ERSTER REPORT
# ─────────────────────────────────────────────────────────────────────────────

def _add_no_data_view(
    elements: List,
    styles: Dict,
    legacy_mode: bool = False,
    technical_json: Optional[Dict] = None,
    evaluation: Optional[Dict] = None,
) -> None:
    """
    Beim ersten Report gibt es keine Vergleichsdaten.
    Statt einer leeren Seite: aktiver Text der den Wert
    kontinuierlicher Analyse erklärt und das Abo verkauft.
    """
    if legacy_mode:
        elements.append(Paragraph(
            "Keine historischen Daten für Trendanalyse vorhanden.",
            styles["normal"]
        ))
        return

    # Aktuellen Exposure-Score ermitteln für Baseline-Ankündigung
    exposure_score = None
    if evaluation and isinstance(evaluation, dict):
        exposure_score = evaluation.get("exposure_score")

    # Haupttext
    elements.append(Paragraph(
        "Dies ist die erste Analyse für dieses Asset. "
        "Ab dem zweiten Report wird hier der Vergleich zum Vormonat dargestellt — "
        "mit Tabelle, Trenddiagramm und Interpretation.",
        styles["normal"]
    ))
    elements.append(Spacer(1, 10))

    # Baseline-Ankündigung
    baseline_text = (
        f"Aktuelle Baseline: Exposure-Level {exposure_score}/5 — "
        "dieser Wert dient als Referenzpunkt für alle zukünftigen Messungen."
        if exposure_score is not None
        else
        "Der aktuelle Stand wird als Baseline für alle zukünftigen Messungen gespeichert."
    )
    elements.append(Paragraph(baseline_text, styles["normal"]))
    elements.append(Spacer(1, 14))

    # Warum Kontinuität wichtig ist — drei Punkte
    elements.append(Paragraph(
        "<b>Warum regelmäßige Messungen entscheidend sind:</b>",
        styles.get("heading3", styles["normal"])
    ))
    elements.append(Spacer(1, 6))

    points = [
        (
            "Angriffsflächen verändern sich monatlich.",
            "Neue Dienste, abgelaufene Zertifikate, frisch veröffentlichte CVEs — "
            "eine einmalige Momentaufnahme zeigt nur den Stand heute, nicht die Entwicklung."
        ),
        (
            "Maßnahmen brauchen Nachweis.",
            "Wer in Sicherheit investiert, muss zeigen können dass es wirkt. "
            "Monatliche Reports dokumentieren Fortschritte nachweisbar — "
            "für interne Stakeholder, Auditoren und Versicherungen."
        ),
        (
            "Frühwarnung statt Reaktion.",
            "Ein neuer öffentlich erreichbarer Port oder ein neu entdeckter "
            "kritischer Dienst wird im nächsten Report sofort sichtbar — "
            "bevor Angreifer ihn ausnutzen können."
        ),
    ]

    for title, body in points:
        elements.append(Paragraph(
            f"• <b>{title}</b>",
            styles["bullet"]
        ))
        elements.append(Paragraph(
            f"  {body}",
            styles.get("small", styles["normal"])
        ))
        elements.append(Spacer(1, 4))

    elements.append(Spacer(1, 10))

    # Nächster Schritt
    elements.append(Paragraph(
        "Der nächste Report erscheint im Folgemonat und enthält den vollständigen Vergleich.",
        styles["normal"]
    ))


# ─────────────────────────────────────────────────────────────────────────────
# MIT VERGLEICHSMONAT — AB DEM ZWEITEN REPORT
# ─────────────────────────────────────────────────────────────────────────────

def _add_comparison_view(
    elements: List,
    styles: Dict,
    trend_text: str,
    compare_month: str,
    trend_table: Optional[Dict[str, Any]] = None,
    legacy_mode: bool = False,
    theme: Optional[Any] = None,
    technical_json: Optional[Dict[str, Any]] = None,
    evaluation: Optional[Dict[str, Any]] = None,
) -> None:
    cmp_lower = (compare_month or "").lower()
    if cmp_lower.endswith("analyse"):
        header_text = f"<b>Veränderung zur {compare_month}</b>"
    else:
        header_text = f"<b>Veränderung zur {compare_month}-Analyse</b>"

    elements.append(Paragraph(header_text, styles["normal"]))
    elements.append(Spacer(1, 6))

    if trend_table:
        _build_trend_table(elements, styles, trend_table, theme)
    else:
        _build_trend_table_fallback(elements, styles)

    # Exposure-Level Diagramm
    try:
        prev_exposure = None
        curr_exposure = None
        if isinstance(technical_json, dict):
            prev_exposure = technical_json.get("previous_exposure_score")
        if isinstance(evaluation, dict):
            curr_exposure = evaluation.get("exposure_score")

        if prev_exposure is not None and curr_exposure is not None:
            elements.append(Paragraph(
                "<b>Exposure-Level Verlauf</b>",
                styles["normal"]
            ))
            elements.append(Spacer(1, 4))
            elements.append(_build_exposure_trend_chart(
                prev_exposure, curr_exposure, compare_month, theme
            ))
            elements.append(Spacer(1, 10))
    except Exception:
        pass

    # Interpretation
    elements.append(Paragraph("<b>Interpretation:</b>", styles["normal"]))
    elements.append(Spacer(1, 4))
    interp = _build_interpretation(trend_table)
    elements.append(Paragraph(interp, styles["normal"]))
    elements.append(Spacer(1, 8))

    # Kontexttext zu den Metriken
    _add_metrics_context(elements, styles, trend_table)


def _build_trend_table(
    elements: List,
    styles: Dict,
    trend_table: Dict[str, Any],
    theme: Optional[Any] = None,
) -> None:
    """Baut die Vergleichstabelle mit farbigen Bewertungszellen."""

    header_cells = [
        Paragraph("<b>Kategorie</b>", styles["normal"]),
        Paragraph("<b>Vormonat</b>", styles["normal"]),
        Paragraph("<b>Aktuell</b>", styles["normal"]),
        Paragraph("<b>Bewertung</b>", styles["normal"]),
    ]
    table_data = [header_cells]

    for cat, vals in trend_table.items():
        prev = vals[0]
        curr = vals[1]
        rating = vals[2]

        # Farbe der Bewertungszelle
        rating_lower = str(rating).lower()
        if "verschlechtert" in rating_lower or "neu" in rating_lower:
            rating_color = HexColor("#fef2f2")
            rating_text_color = "#991b1b"
        elif "verbessert" in rating_lower:
            rating_color = HexColor("#f0fdf4")
            rating_text_color = "#166534"
        else:
            rating_color = HexColor("#f8fafc")
            rating_text_color = "#374151"

        row = [
            Paragraph(_display_category_label(cat), styles["normal"]),
            Paragraph(str(prev), styles["normal"]),
            Paragraph(str(curr), styles["normal"]),
            Paragraph(
                f"<font color='{rating_text_color}'>{rating}</font>",
                styles["normal"]
            ),
        ]
        table_data.append(row)

    tbl = Table(table_data, colWidths=[55 * mm, 22 * mm, 22 * mm, 40 * mm])
    set_table_repeat(tbl, 1)
    set_table_no_split(tbl)

    border_color = HexColor("#e5e7eb")
    header_bg = HexColor("#f8fafc")

    style = TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.3, border_color),
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#111827")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (1, 1), (2, -1), "CENTER"),
    ])

    # Zeilenfarben für Bewertungsspalte
    for i, (cat, vals) in enumerate(trend_table.items(), start=1):
        rating = str(vals[2]).lower()
        if "verschlechtert" in rating or "neu" in rating:
            style.add("BACKGROUND", (3, i), (3, i), HexColor("#fef2f2"))
        elif "verbessert" in rating:
            style.add("BACKGROUND", (3, i), (3, i), HexColor("#f0fdf4"))

    tbl.setStyle(style)
    elements.append(tbl)
    elements.append(Spacer(1, 8))

    if "Kritische Services" in trend_table:
        elements.append(Paragraph(
            "<i>Hinweis: Kritische Services = öffentlich erreichbare Administrations- "
            "oder Managementdienste (RDP, SSH, VNC, Datenbankzugänge).</i>",
            styles.get("small", styles["normal"])
        ))
        elements.append(Spacer(1, 6))


def _build_trend_table_fallback(elements: List, styles: Dict) -> None:
    """Fallback wenn keine strukturierten Trenddaten vorliegen."""
    lines = [
        "<b>Kategorie          Vormonat  Aktuell  Bewertung</b>",
        "─────────────────────────────────────────────────",
        "Öffentl. Ports           —        —    erste Messung",
        "Krit. Services           —        —    erste Messung",
        "Hochrisiko-CVEs          —        —    erste Messung",
        "TLS-Schwächen            —        —    erste Messung",
    ]
    for line in lines:
        elements.append(Paragraph(line, styles["normal"]))
    elements.append(Spacer(1, 8))


def _add_metrics_context(
    elements: List,
    styles: Dict,
    trend_table: Optional[Dict[str, Any]],
) -> None:
    """
    Erklärt die Metriken in einem kurzen Absatz — damit der Geschäftsführer
    die Zahlen einordnen kann ohne IT-Hintergrund.
    """
    if not trend_table:
        return

    context_parts = []

    ports_vals = trend_table.get("Öffentliche Ports")
    crit_vals = trend_table.get("Kritische Services")
    cve_vals = trend_table.get("Hochrisiko-CVEs")
    tls_vals = trend_table.get("TLS-Schwächen")

    try:
        if ports_vals and int(ports_vals[1]) > 0:
            context_parts.append(
                f"<b>Öffentliche Ports ({ports_vals[1]}):</b> Jeder öffentlich erreichbare "
                "Port ist ein potenzieller Einstiegspunkt. Weniger ist besser."
            )
        if crit_vals and int(crit_vals[1]) > 0:
            context_parts.append(
                f"<b>Kritische Services ({crit_vals[1]}):</b> Administrationsdienste "
                "(RDP, SSH, Datenbank) sollten nicht direkt aus dem Internet erreichbar sein."
            )
        if cve_vals and int(cve_vals[1]) > 0:
            context_parts.append(
                f"<b>Hochrisiko-CVEs ({cve_vals[1]}):</b> Bekannte Schwachstellen "
                "(CVSS ≥9) in eingesetzter Software. Patches reduzieren diesen Wert."
            )
        if tls_vals and int(tls_vals[1]) > 0:
            context_parts.append(
                f"<b>TLS-Schwächen ({tls_vals[1]}):</b> Probleme in der "
                "Verschlüsselungskonfiguration — z. B. abgelaufene Zertifikate "
                "oder schwache Cipher-Suites."
            )
    except Exception:
        return

    if not context_parts:
        return

    elements.append(Paragraph(
        "<b>Was die Kennzahlen bedeuten:</b>",
        styles.get("heading3", styles["normal"])
    ))
    elements.append(Spacer(1, 5))

    for part in context_parts:
        elements.append(Paragraph(f"• {part}", styles["bullet"]))
        elements.append(Spacer(1, 3))

    elements.append(Spacer(1, 6))


# ─────────────────────────────────────────────────────────────────────────────
# INTERPRETATION
# ─────────────────────────────────────────────────────────────────────────────

def _build_interpretation(trend_table: Optional[Dict[str, Any]]) -> str:
    if not trend_table:
        return "Die Angriffsfläche ist stabil."

    worsening = []
    improving = []
    stable = []

    for cat, vals in trend_table.items():
        try:
            prev = int(vals[0])
            curr = int(vals[1])
        except Exception:
            stable.append(cat)
            continue

        if curr > prev:
            worsening.append((cat, curr - prev))
        elif curr < prev:
            improving.append((cat, prev - curr))
        else:
            stable.append(cat)

    def _label(cat):
        mapping = {
            "Öffentliche Ports": "öffentliche Dienste",
            "Kritische Services": "Administrationsdienste",
            "Hochrisiko-CVEs": "kritische Schwachstellen",
            "TLS-Schwächen": "Kryptokonfiguration",
        }
        return mapping.get(cat, cat)

    # Alle verschlechtert
    if worsening and not improving:
        cats = ", ".join(_label(c) for c, _ in worsening)
        if len(worsening) == 1 and worsening[0][0] == "TLS-Schwächen":
            return (
                "Die Angriffsfläche ist weitgehend stabil, zeigt jedoch eine Verschlechterung "
                "in der Kryptokonfiguration. TLS-Zertifikate und Cipher-Suites sollten "
                "zeitnah überprüft werden."
            )
        if len(worsening) == 1 and worsening[0][0] == "Hochrisiko-CVEs":
            return (
                f"Die Anzahl kritischer Schwachstellen ist um {worsening[0][1]} gestiegen. "
                "Dies weist auf neu veröffentlichte CVEs für die eingesetzte Software hin. "
                "Patches werden zeitnah empfohlen."
            )
        return (
            f"Die Angriffsfläche zeigt eine Verschlechterung bei: {cats}. "
            "Handlungsempfehlungen beachten und Maßnahmen priorisieren."
        )

    # Alle verbessert
    if improving and not worsening:
        cats = ", ".join(_label(c) for c, _ in improving)
        return (
            f"Die Angriffsfläche hat sich verbessert, insbesondere bei: {cats}. "
            "Umgesetzte Maßnahmen zeigen Wirkung — dieser Trend sollte fortgesetzt werden."
        )

    # Gemischt
    if worsening and improving:
        worse = ", ".join(_label(c) for c, _ in worsening)
        better = ", ".join(_label(c) for c, _ in improving)
        return (
            f"Die Angriffsfläche zeigt gemischte Entwicklung: Verbesserung bei {better}, "
            f"Verschlechterung bei {worse}. Weitere Maßnahmen priorisieren."
        )

    return "Die Angriffsfläche ist stabil. Keine signifikanten Veränderungen zum Vormonat."


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY VIEW (kein Vergleich aber Trend-Text vorhanden)
# ─────────────────────────────────────────────────────────────────────────────

def _add_history_view(elements: List, styles: Dict, trend_text: str) -> None:
    elements.append(Paragraph("<b>Entwicklung der Angriffsfläche</b>", styles["normal"]))
    elements.append(Spacer(1, 4))
    for line in trend_text.splitlines():
        if line.strip():
            elements.append(Paragraph(f"• {line.strip()}", styles["bullet"]))


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSURE-LEVEL DIAGRAMM
# ─────────────────────────────────────────────────────────────────────────────

def _build_exposure_trend_chart(
    prev_score: int,
    curr_score: int,
    compare_month: str,
    theme: Optional[Any] = None,
) -> Drawing:
    """
    Visualisiert den Exposure-Level Verlauf als einfaches Liniendiagramm.
    Größer und lesbarer als vorher.
    """
    width = 100 * mm
    height = 30 * mm
    padding_x = 12 * mm
    padding_y = 6 * mm
    chart_h = height - 2 * padding_y

    def _y(val: int) -> float:
        val = max(1, min(5, int(val)))
        return padding_y + (val - 1) * (chart_h / 4)

    # Farben
    primary = getattr(theme, "primary", HexColor("#1a365d")) if theme else HexColor("#1a365d")
    danger = HexColor("#dc2626")
    success = HexColor("#16a34a")
    grid_color = HexColor("#e5e7eb")

    d = Drawing(width, height)

    # Hintergrund-Gitterlinien (1-5)
    for level in range(1, 6):
        y = _y(level)
        d.add(Line(padding_x - 3 * mm, y, width - padding_x + 3 * mm, y,
                   strokeColor=grid_color, strokeWidth=0.3))
        d.add(String(2 * mm, y - 2, str(level), fontSize=6,
                     fillColor=HexColor("#9ca3af")))

    x1 = padding_x
    x2 = width - padding_x
    y1 = _y(prev_score)
    y2 = _y(curr_score)

    # Trendlinie
    line_color = danger if curr_score > prev_score else (success if curr_score < prev_score else primary)
    d.add(Line(x1, y1, x2, y2, strokeColor=line_color, strokeWidth=1.5))

    # Punkte
    d.add(Circle(x1, y1, 2 * mm, fillColor=primary, strokeColor=primary))
    d.add(Circle(x2, y2, 2 * mm, fillColor=line_color, strokeColor=line_color))

    # Score-Labels über den Punkten
    d.add(String(x1 - 2 * mm, y1 + 3 * mm, str(prev_score),
                 fontSize=8, fillColor=primary))
    d.add(String(x2 + 1 * mm, y2 + 3 * mm, str(curr_score),
                 fontSize=8, fillColor=line_color))

    # X-Achsen-Labels
    d.add(String(x1 - 4 * mm, 1.5 * mm,
                 str(compare_month or "Vormonat")[:10],
                 fontSize=7, fillColor=HexColor("#6b7280")))
    d.add(String(x2 - 8 * mm, 1.5 * mm, "Aktuell",
                 fontSize=7, fillColor=HexColor("#6b7280")))

    return d


# ─────────────────────────────────────────────────────────────────────────────
# HILFSFUNKTIONEN
# ─────────────────────────────────────────────────────────────────────────────

def _display_category_label(category: str) -> str:
    if category == "Kritische Services":
        return "Kritische Administrationsdienste"
    return str(category)


def _format_interpretation_label(category: str) -> str:
    mapping = {
        "Öffentliche Ports": "öffentliche Dienste/Ports",
        "Kritische Services": "öffentliche Managementdienste",
        "Hochrisiko-CVEs": "Schwachstellenlage",
        "TLS-Schwächen": "Kryptokonfiguration",
    }
    return mapping.get(category, str(category))


def _derive_trend_table(
    technical_json: Dict[str, Any],
    evaluation: Optional[Dict[str, Any]],
) -> Dict[str, Tuple[int, int, str]]:
    """
    Leitet eine strukturierte Trend-Tabelle aus vorhandenen Snapshot-Daten ab.
    Wird aufgerufen wenn compare_month gesetzt aber kein trend_table übergeben wurde.
    """

    def _count_open_ports(tj):
        return len(tj.get("open_ports") or tj.get("services") or [])

    def _count_critical_services(tj):
        cnt = 0
        for s in (tj.get("open_ports") or tj.get("services") or []):
            try:
                if isinstance(s, dict):
                    if s.get("_version_risk", 0) or s.get("version_risk", 0) or s.get("critical", False):
                        cnt += 1
                else:
                    if getattr(s, "_version_risk", 0) or getattr(s, "version_risk", 0) or getattr(s, "critical", False):
                        cnt += 1
            except Exception:
                continue
        return max(cnt, len(tj.get("critical_services") or []))

    def _count_high_risk_cves(tj, ev):
        cves = []
        cves.extend(tj.get("vulnerabilities") or [])
        cves.extend(tj.get("cve_enriched") or [])
        for s in (tj.get("open_ports") or tj.get("services") or []):
            if isinstance(s, dict):
                cves.extend(s.get("vulnerabilities") or [])
            else:
                cves.extend(getattr(s, "vulnerabilities", []) or [])
        if ev:
            cves.extend(ev.get("cves") or [])

        by_id = {}
        for c in cves:
            try:
                if isinstance(c, dict):
                    cid = c.get("id") or c.get("cve") or ""
                    cvss = float(c.get("cvss") or 0)
                else:
                    cid = str(c)
                    cvss = 0.0
                if cid and (cid not in by_id or cvss > by_id[cid]):
                    by_id[cid] = cvss
            except Exception:
                continue
        return sum(1 for v in by_id.values() if v >= 9.0)

    def _count_tls_weaknesses(tj):
        cnt = 0
        cnt += len(tj.get("tls_weaknesses") or tj.get("ssl_weaknesses") or [])
        for s in (tj.get("open_ports") or tj.get("services") or []):
            try:
                if isinstance(s, dict):
                    si = s.get("ssl_info") or {}
                    port = s.get("port")
                    if si and (si.get("has_weak_cipher") or si.get("weaknesses") or si.get("issues")):
                        cnt += 1
                    if s.get("tls_weakness") or s.get("ssl_weakness"):
                        cnt += 1
                    if port in {443, 8443, 9443} and not si and not s.get("is_ssl"):
                        cnt += 1
                else:
                    si = getattr(s, "ssl_info", None)
                    port = getattr(s, "port", None)
                    if si and (getattr(si, "has_weak_cipher", False) or getattr(si, "weaknesses", None)):
                        cnt += 1
                    if port in {443, 8443, 9443} and not si:
                        cnt += 1
            except Exception:
                continue
        return cnt

    current = {
        "Öffentliche Ports":    _count_open_ports(technical_json),
        "Kritische Services":   _count_critical_services(technical_json),
        "Hochrisiko-CVEs":      _count_high_risk_cves(technical_json, evaluation),
        "TLS-Schwächen":        _count_tls_weaknesses(technical_json),
    }

    # Vormonat aus technical_json oder evaluation laden
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
        for k in current.keys():
            if k in prev_source:
                prev[k] = int(prev_source.get(k) or 0)
        if not prev:
            prev = {
                "Öffentliche Ports":   _count_open_ports(prev_source),
                "Kritische Services":  _count_critical_services(prev_source),
                "Hochrisiko-CVEs":     _count_high_risk_cves(prev_source, None),
                "TLS-Schwächen":       _count_tls_weaknesses(prev_source),
            }
    else:
        prev = {k: 0 for k in current.keys()}

    trend_table = {}
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
    diff = prev - curr
    return "leicht verbessert" if diff == 1 else "verbessert"