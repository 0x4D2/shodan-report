"""
Trend-Analyse Section für PDF-Reports.
Vergleicht aktuelle Messung mit Vormonat und kommuniziert
Veränderungen klar und management-tauglich.
"""

from typing import List, Dict, Optional, Any, Tuple
from reportlab.platypus import Spacer, Paragraph, Table, TableStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.graphics.shapes import Drawing, Line, Circle, String, Rect, PolyLine
from shodan_report.pdf.layout import keep_section, set_table_repeat
from shodan_report.pdf.styles import Colors


# ── Farben — alle aus dem globalen Designsystem ──────────────────────────────
C_BORDER     = Colors.border       # #e5e7eb
C_HEADER_BG  = Colors.bg_light     # #f8fafc
C_NEUTRAL_BG = Colors.bg_light     # #f8fafc
C_TEXT       = Colors.text         # #111827
C_MUTED      = Colors.text_muted   # #6b7280
C_RED_BG     = Colors.risk_critical_bg   # #fef2f2
C_RED        = Colors.risk_critical_dot  # #dc2626
C_GREEN_BG   = Colors.risk_low_bg        # #f0fdf4
C_GREEN      = Colors.risk_low_dot       # #16a34a
C_ORANGE     = Colors.risk_high_dot      # #ea580c
C_ORANGE_BG  = Colors.risk_high_bg       # #fff7ed
C_CHART_LINE = Colors.accent             # #1e56a0
C_GRID       = Colors.border             # #e5e7eb


# ─────────────────────────────────────────────────────────────────────────────
# HAUPTFUNKTION
# ─────────────────────────────────────────────────────────────────────────────

def create_trend_section(elements: List, styles: Dict, *args, **kwargs) -> None:
    trend_text     = kwargs.get("trend_text", "")
    compare_month  = kwargs.get("compare_month", None)
    legacy_mode    = kwargs.get("legacy_mode", False)
    trend_table    = kwargs.get("trend_table", None)
    technical_json = kwargs.get("technical_json", None)
    evaluation     = kwargs.get("evaluation", None)
    theme          = kwargs.get("theme", None)

    if "context" in kwargs and kwargs.get("context") is not None:
        ctx = kwargs["context"]
        trend_text     = getattr(ctx, "trend_text", trend_text)
        compare_month  = getattr(ctx, "compare_month", compare_month)
        technical_json = getattr(ctx, "technical_json", technical_json)
        evaluation     = getattr(ctx, "evaluation", evaluation)

    elements.append(Spacer(1, 12))
    heading_style = styles.get("heading1", styles.get("heading2"))
    elements.append(keep_section([
        Paragraph("<b>7. Trend- &amp; Vergleichsanalyse</b>", heading_style),
        Spacer(1, 8),
    ]))

    if compare_month:
        if not trend_table:
            trend_table = _derive_trend_table(technical_json or {}, evaluation)
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
    if legacy_mode:
        elements.append(Paragraph(
            "Keine historischen Daten für Trendanalyse vorhanden.",
            styles["normal"]
        ))
        return

    exposure_score = None
    if evaluation is not None:
        try:
            from shodan_report.pdf.sections.data.management_data import (
                compute_boosted_exposure_score,
                prepare_management_data,
            )
            _mdata = prepare_management_data(technical_json or {}, evaluation)
            _base  = _mdata.get("exposure_score", 1)
            exposure_score = compute_boosted_exposure_score(
                _base, technical_json or {}, _mdata.get("cve_count", 0)
            )
        except Exception:
            exposure_score = (
                evaluation.get("exposure_score")
                if isinstance(evaluation, dict)
                else getattr(evaluation, "exposure_score", None)
            )

    elements.append(Paragraph(
        "Dies ist die erste Analyse für dieses Asset. "
        "Ab dem zweiten Report wird hier der Vergleich zum Vormonat dargestellt — "
        "mit Tabelle, Trenddiagramm und Interpretation.",
        styles["normal"]
    ))
    elements.append(Spacer(1, 10))

    baseline_text = (
        f"Aktuelle Baseline: Exposure-Level {exposure_score}/5 — "
        "dieser Wert dient als Referenzpunkt für alle zukünftigen Messungen."
        if exposure_score is not None
        else
        "Der aktuelle Stand wird als Baseline für alle zukünftigen Messungen gespeichert."
    )
    elements.append(Paragraph(baseline_text, styles["normal"]))
    elements.append(Spacer(1, 14))

    elements.append(Paragraph(
        "<b>Warum regelmäßige Messungen entscheidend sind:</b>",
        styles.get("heading3", styles["normal"])
    ))
    elements.append(Spacer(1, 6))

    points = [
        (
            "Angriffsflächen verändern sich monatlich.",
            "Neue Dienste, abgelaufene Zertifikate, frisch veröffentlichte CVEs — "
            "eine einmalige Momentaufnahme zeigt nur den Stand heute, nicht die Entwicklung.",
        ),
        (
            "Maßnahmen brauchen Nachweis.",
            "Wer in Sicherheit investiert, muss zeigen können dass es wirkt. "
            "Monatliche Reports dokumentieren Fortschritte nachweisbar — "
            "für interne Stakeholder, Auditoren und Versicherungen.",
        ),
        (
            "Frühwarnung statt Reaktion.",
            "Ein neuer öffentlich erreichbarer Port oder ein neu entdeckter "
            "kritischer Dienst wird im nächsten Report sofort sichtbar — "
            "bevor Angreifer ihn ausnutzen können.",
        ),
    ]
    for title, body in points:
        elements.append(Paragraph(f"• <b>{title}</b>", styles["bullet"]))
        elements.append(Paragraph(f"  {body}", styles.get("small", styles["normal"])))
        elements.append(Spacer(1, 4))

    elements.append(Spacer(1, 10))
    elements.append(Paragraph(
        "Der nächste Report erscheint im Folgemonat und enthält den vollständigen Vergleich.",
        styles["normal"]
    ))


# ─────────────────────────────────────────────────────────────────────────────
# VERGLEICHSANSICHT — AB DEM ZWEITEN REPORT
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

    # ── Exposure-Level auslesen ───────────────────────────────────────────────
    prev_exposure = None
    curr_exposure = None
    try:
        if isinstance(technical_json, dict):
            prev_exposure = technical_json.get("previous_exposure_score")
        if evaluation is not None:
            try:
                from shodan_report.pdf.sections.data.management_data import (
                    compute_boosted_exposure_score,
                    prepare_management_data,
                )
                _mdata = prepare_management_data(technical_json or {}, evaluation)
                _base  = _mdata.get("exposure_score", 1)
                curr_exposure = compute_boosted_exposure_score(
                    _base, technical_json or {}, _mdata.get("cve_count", 0)
                )
            except Exception:
                curr_exposure = (
                    evaluation.get("exposure_score")
                    if isinstance(evaluation, dict)
                    else getattr(evaluation, "exposure_score", None)
                )
    except Exception:
        pass

    # ── KPI-Karten (oberste Zeile) ────────────────────────────────────────────
    kpi_row = _build_kpi_cards(
        styles, compare_month, trend_table, prev_exposure, curr_exposure
    )
    elements.append(kpi_row)
    elements.append(Spacer(1, 14))

    # ── Zweispaltig: Tabelle links | Chart rechts ─────────────────────────────
    left_col  = _build_comparison_table(styles, trend_table, compare_month, prev_exposure, curr_exposure)
    right_col = _build_chart_cell(
        styles, prev_exposure, curr_exposure, compare_month, trend_table,
        technical_json=technical_json,
    )

    two_col = Table(
        [[left_col, right_col]],
        colWidths=[95 * mm, 85 * mm],
    )
    two_col.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (0, 0), 8),   # Abstand zwischen Spalten
    ]))
    elements.append(two_col)
    elements.append(Spacer(1, 12))

    # ── Interpretationsbox ───────────────────────────────────────────────────
    interp = _build_interpretation(trend_table)
    _build_interpretation_box(elements, styles, interp)

    # ── Kennzahlen-Erklärung ─────────────────────────────────────────────────
    _build_metrics_context(elements, styles)


def _build_metrics_context(elements: List, styles: Dict) -> None:
    """Kurze Erklärung der Kennzahlen — erscheint nach der Interpretationsbox."""
    ns = styles.get("normal") or styles.get("Normal")
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        '<font size="8" color="#6b7280"><b>Was die Kennzahlen bedeuten</b></font>',
        ns,
    ))
    elements.append(Paragraph(
        '<font size="8" color="#6b7280">'
        "Öffentliche Ports: Anzahl extern erreichbarer Dienste · "
        "Kritische Services: Administrationsschnittstellen (SSH, RDP, DB) · "
        "Hochrisiko-CVEs: Schwachstellen mit CVSS ≥ 9,0 · "
        "TLS-Schwächen: Schwache Cipher, abgelaufene oder fehlende Zertifikate"
        "</font>",
        ns,
    ))


# ─────────────────────────────────────────────────────────────────────────────
# KPI-KARTEN (obere Zeile mit 5 Kennzahlen)
# ─────────────────────────────────────────────────────────────────────────────

def _build_kpi_cards(
    styles: Dict,
    compare_month: str,
    trend_table: Optional[Dict],
    prev_exposure: Optional[int],
    curr_exposure: Optional[int],
) -> Table:
    """
    Fünf nebeneinander liegende KPI-Karten wie im Screenshot:
    Vormonat | Aktuell | Veränderung | Neue CVEs | Behobene Ports
    """
    # Werte aus trend_table extrahieren
    ports_prev, ports_curr = _tt_vals(trend_table, "Öffentliche Ports")
    cves_prev,  cves_curr  = _tt_vals(trend_table, "Hochrisiko-CVEs")

    # Farb-Tokens als Strings (für inline <font color="...">)
    _COL_NEUTRAL = "#6b7280"   # Colors.text_muted
    _COL_RED     = "#dc2626"   # Colors.risk_critical_dot
    _COL_GREEN   = "#16a34a"   # Colors.risk_low_dot
    _COL_ORANGE  = "#ea580c"   # Colors.risk_high_dot
    _COL_TEXT    = "#111827"   # Colors.text

    # Exposure-Level
    exp_prev_str = f"{prev_exposure} / 5" if prev_exposure is not None else "— / 5"
    exp_curr_str = f"{curr_exposure} / 5" if curr_exposure is not None else "— / 5"
    exp_curr_color = _COL_ORANGE
    if curr_exposure is not None and prev_exposure is not None:
        if curr_exposure < prev_exposure:
            exp_curr_color = _COL_GREEN
        elif curr_exposure > prev_exposure:
            exp_curr_color = _COL_RED

    # Veränderung
    if curr_exposure is not None and prev_exposure is not None:
        diff = curr_exposure - prev_exposure
        if diff == 0:
            change_val   = "→ Stabil"
            change_sub   = "kein Trend"
            change_color = _COL_NEUTRAL
        elif diff > 0:
            change_val   = f"↑ +{diff}"
            change_sub   = "verschlechtert"
            change_color = _COL_RED
        else:
            change_val   = f"↓ {diff}"
            change_sub   = "verbessert"
            change_color = _COL_GREEN
    else:
        change_val   = "→ Stabil"
        change_sub   = "kein Trend"
        change_color = _COL_NEUTRAL

    # Neue CVEs
    cve_diff = cves_curr - cves_prev
    if cve_diff > 0:
        cve_val   = f"+{cve_diff}"
        cve_sub   = "seit Vormonat"
        cve_color = _COL_RED
    elif cve_diff < 0:
        cve_val   = str(cve_diff)
        cve_sub   = "weniger als Vormonat"
        cve_color = _COL_GREEN
    else:
        cve_val   = "±0"
        cve_sub   = "keine Änderung"
        cve_color = _COL_NEUTRAL

    # Behobene Ports
    port_diff = ports_prev - ports_curr
    if port_diff > 0:
        port_val   = f"−{port_diff}"
        port_sub   = _port_closed_label(trend_table)
        port_color = _COL_GREEN
    elif port_diff < 0:
        port_val   = f"+{abs(port_diff)}"
        port_sub   = "neu geöffnet"
        port_color = _COL_RED
    else:
        port_val   = "±0"
        port_sub   = "unverändert"
        port_color = _COL_NEUTRAL

    # Die Interpretationsbox ist 183 mm breit, daher passen wir die KPI-Tabelle daran an
    _CARD_W = 183.0 / 5 * mm  # 36.6 mm

    def _card(top_label, big_val, big_color, sub_val, sub_color=None):
        _big_color  = big_color if isinstance(big_color, str) else "#111827"
        _sub_color  = (sub_color if isinstance(sub_color, str) else "#6b7280") if sub_color else "#6b7280"
        return Table(
            [
                [Paragraph(f'<font size="7" color="#6b7280">{top_label}</font>', styles["normal"])],
                [Paragraph(f'<font size="14" color="{_big_color}"><b>{big_val}</b></font>', styles["normal"])],
                [Paragraph(f'<font size="7.5" color="{_sub_color}">{sub_val}</font>', styles["normal"])],
            ],
            colWidths=[_CARD_W],
        )

    cards = [
        _card("VORMONAT",        exp_prev_str,  _COL_TEXT, compare_month or "Vormonat"),
        _card("AKTUELL",         exp_curr_str,  exp_curr_color, _next_month_label(compare_month)),
        _card("VERÄNDERUNG",     change_val,    change_color,   change_sub),
        _card("NEUE CVES",       cve_val,       cve_color,      cve_sub),
        _card("BEHOBENE PORTS",  port_val,      port_color,     port_sub),
    ]

    # Kartenstyle — identisch zu Management-KPI-Zellen
    card_style = TableStyle([
        ("BOX",           (0, 0), (-1, -1), 0.3, C_BORDER),
        ("BACKGROUND",    (0, 0), (-1, -1), C_NEUTRAL_BG),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ])
    for c in cards:
        c.setStyle(card_style)

    row_tbl = Table([[c for c in cards]], colWidths=[_CARD_W] * 5)  # 5×36.6=183 mm
    row_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return row_tbl


# ─────────────────────────────────────────────────────────────────────────────
# VERGLEICHSTABELLE (linke Spalte)
# ─────────────────────────────────────────────────────────────────────────────

def _build_comparison_table(
    styles: Dict,
    trend_table: Optional[Dict],
    compare_month: str,
    prev_exposure: Optional[int] = None,
    curr_exposure: Optional[int] = None,
) -> Table:
    """
    Tabelle: KENNZAHL | MÄR 2026 | APR 2026 | TREND
    Kopfzeile grau hinterlegt, Trend-Spalte farbig.
    """
    prev_label = _format_month_label(compare_month or "Vormonat")
    curr_label = "AKTUELL"

    header = [
        Paragraph(f'<font size="8" color="#6b7280"><b>KENNZAHL</b></font>',   styles["normal"]),
        Paragraph(f'<font size="8" color="#6b7280"><b>{prev_label}</b></font>', styles["normal"]),
        Paragraph(f'<font size="8" color="#6b7280"><b>{curr_label}</b></font>', styles["normal"]),
        Paragraph(f'<font size="8" color="#6b7280"><b>TREND</b></font>',       styles["normal"]),
    ]

    # Zeilen aus trend_table
    DISPLAY_ROWS = [
        ("Exposure-Level",   "Öffentliche Ports",  "exposure"),
        ("Offene Ports",     "Öffentliche Ports",  "ports"),
        ("CVEs gesamt",      "Hochrisiko-CVEs",     "cves"),
        ("Kritisch (≥9)",    "Hochrisiko-CVEs",     "crit"),
        ("CISA KEV",         "CISA KEV",            "kev"),
        ("Ablaufende Zert.", "TLS-Schwächen",       "tls"),
    ]

    rows = [header]
    tt = trend_table or {}


    # prev_exposure und curr_exposure werden jetzt direkt übergeben

    for display_name, tt_key, row_type in DISPLAY_ROWS:
        prev_v, curr_v = _tt_vals(tt, tt_key)

        if display_name == "Exposure-Level":
            # Zeige Skalenbewertung (z.B. 4/5) statt absolute Ports
            prev_disp = f"{prev_exposure} / 5" if prev_exposure is not None else "— / 5"
            curr_disp = f"{curr_exposure} / 5" if curr_exposure is not None else "— / 5"
            # Trend aus Skalenwerten berechnen
            if prev_exposure is not None and curr_exposure is not None:
                diff = curr_exposure - prev_exposure
            else:
                diff = 0
        else:
            prev_disp = str(prev_v)
            curr_disp = str(curr_v)
            diff = curr_v - prev_v

        if diff > 0:
            trend_str  = f"↑ +{diff}"
            trend_color = "#dc2626"
            row_bg      = None
        elif diff < 0:
            trend_str  = f"↓ {diff}"
            trend_color = "#16a34a"
            row_bg      = None
        else:
            trend_str  = "–"
            trend_color = "#6b7280"
            row_bg      = None

        rows.append([
            Paragraph(f'<font size="9" color="#111827">{display_name}</font>', styles["normal"]),
            Paragraph(f'<font size="9" color="#6b7280">{prev_disp}</font>',        styles["normal"]),
            Paragraph(f'<font size="9" color="#111827"><b>{curr_disp}</b></font>', styles["normal"]),
            Paragraph(f'<font size="9" color="{trend_color}"><b>{trend_str}</b></font>', styles["normal"]),
        ])

    tbl = Table(rows, colWidths=[38 * mm, 18 * mm, 18 * mm, 18 * mm])
    set_table_repeat(tbl, 1)

    ts = TableStyle([
        # Header
        ("BACKGROUND",    (0, 0), (-1, 0), C_HEADER_BG),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (1, 0), (-1, -1), "CENTER"),
    ])
    tbl.setStyle(ts)
    return tbl


# ─────────────────────────────────────────────────────────────────────────────
# CHART-ZELLE (rechte Spalte)
# ─────────────────────────────────────────────────────────────────────────────

def _build_chart_cell(
    styles: Dict,
    prev_exposure: Optional[int],
    curr_exposure: Optional[int],
    compare_month: str,
    trend_table: Optional[Dict],
    technical_json: Optional[Dict] = None,
) -> Table:
    """
    Rechte Spalte: Exposure-Level Verlauf als Linien-Chart.
    Nutzt echte historische Daten aus technical_json['exposure_history'] wenn vorhanden,
    sonst Fallback auf 2-Punkt-Darstellung (Vormonat → Aktuell).
    """
    exposure_history = (technical_json or {}).get("exposure_history")
    chart, n_months = _build_multi_point_chart(
        prev_exposure, curr_exposure, compare_month, exposure_history
    )

    n_label = f"{n_months} MONATE" if n_months > 1 else "AKTUELL"

    # Legende
    legend = Paragraph(
        '<font size="8" color="#ea580c">— Exposure-Level</font>',
        styles["normal"]
    )

    inner = Table(
        [
            [Paragraph(f'<font size="8" color="#6b7280"><b>EXPOSURE-LEVEL VERLAUF ({n_label})</b></font>', styles["normal"])],
            [chart],
            [legend],
        ],
        colWidths=[83 * mm],
    )
    inner.setStyle(TableStyle([
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("BACKGROUND",    (0, 0), (-1, -1), white),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    return inner


def _build_multi_point_chart(
    prev_score: Optional[int],
    curr_score: Optional[int],
    compare_month: str,
    exposure_history: Optional[list] = None,
) -> Tuple[Drawing, int]:
    """
    Liniendiagramm mit echten Datenpunkten aus exposure_history.
    Fallback auf 2-Punkt-Darstellung wenn keine History vorhanden.
    Gibt (Drawing, Anzahl_Monate) zurück.
    """
    w = 75 * mm
    h = 28 * mm
    px = 10 * mm   # padding x
    py = 5 * mm    # padding y
    chart_h = h - 2 * py
    chart_w = w - 2 * px

    # ── Datenpunkte aus echter History aufbauen ───────────────────────────────
    if exposure_history and len(exposure_history) >= 2:
        points = [max(1, min(5, int(e["score"]))) for e in exposure_history]
        months = [_month_abbr(e["month"]) for e in exposure_history]
        n_months = len(points)
    else:
        # Fallback: nur Vormonat + Aktuell (2 Punkte, kein Fake-Jitter)
        p = int(prev_score) if prev_score is not None else 3
        c = int(curr_score)  if curr_score  is not None else 3
        points = [p, c]
        raw_months = _derive_chart_months(compare_month)
        months = [raw_months[-2], raw_months[-1]]  # Vor + Akt
        n_months = 2

    n_slots = max(len(points), 2)
    x_step = chart_w / max(n_slots - 1, 1)

    def _xpos(i):
        return px + i * x_step

    def _ypos(v):
        v = max(1, min(5, v))
        return py + (v - 1) * (chart_h / 4)

    d = Drawing(w, h)

    # Gitterlinien (horizontal, Level 1–5)
    for level in range(1, 6):
        y = _ypos(level)
        d.add(Line(px, y, w - px, y, strokeColor=C_GRID, strokeWidth=0.4))
        d.add(String(1 * mm, y - 2, str(level), fontSize=6,
                     fillColor=HexColor("#CCCCCC")))

    # Linie zwischen Punkten
    for i in range(len(points) - 1):
        x1 = _xpos(i)
        x2 = _xpos(i + 1)
        y1 = _ypos(points[i])
        y2 = _ypos(points[i + 1])
        d.add(Line(x1, y1, x2, y2,
                   strokeColor=C_CHART_LINE, strokeWidth=1.5))

    # Punkte
    for i, val in enumerate(points):
        x = _xpos(i)
        y = _ypos(val)
        is_last = (i == len(points) - 1)
        r = 1.8 * mm if not is_last else 2.2 * mm
        if is_last:
            # Letzter Punkt: weißer Ring drum
            d.add(Circle(x, y, r + 0.8 * mm,
                         fillColor=white, strokeColor=C_CHART_LINE,
                         strokeWidth=0.8))
        d.add(Circle(x, y, r, fillColor=C_CHART_LINE, strokeColor=C_CHART_LINE, strokeWidth=0))

    # X-Achsen-Labels
    for i, label in enumerate(months):
        x = _xpos(i)
        is_last = (i == len(months) - 1)
        color = "#ea580c" if is_last else "#AAAAAA"
        d.add(String(x - 3 * mm, 1 * mm, label, fontSize=7,
                     fillColor=HexColor(color)))

    return d, n_months


def _month_abbr(month_str: str) -> str:
    """Konvertiert 'YYYY-MM' in dreistellige Monatsabkürzung, z.B. '2026-04' → 'Apr'."""
    _num_to_abbr = {
        1:"Jan",2:"Feb",3:"Mär",4:"Apr",5:"Mai",6:"Jun",
        7:"Jul",8:"Aug",9:"Sep",10:"Okt",11:"Nov",12:"Dez"
    }
    try:
        import re
        m = re.match(r"(\d{4})-(\d{1,2})", month_str.strip())
        if m:
            return _num_to_abbr.get(int(m.group(2)), month_str)
    except Exception:
        pass
    return month_str


def _jitter(seed: int) -> int:
    """Deterministisches kleines Rauschen für simulierte Verlaufswerte (Legacy-Fallback)."""
    jitters = [0, 1, 0, -1, 1, 0, -1, 0]
    return jitters[seed % len(jitters)]


# ─────────────────────────────────────────────────────────────────────────────
# INTERPRETATIONSBOX
# ─────────────────────────────────────────────────────────────────────────────

def _build_interpretation_box(
    elements: List,
    styles: Dict,
    interp: str,
) -> None:
    """
    Grau hinterlegte Box mit Interpretation — wie im Screenshot.
    """
    cell = Paragraph(
        f'<font size="9" color="#111827"><b>Interpretation:</b> {interp}</font>',
        styles["normal"]
    )
    tbl = Table([[cell]], colWidths=[183 * mm])
    tbl.setStyle(TableStyle([
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("BACKGROUND",    (0, 0), (-1, -1), C_NEUTRAL_BG),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    elements.append(tbl)
    elements.append(Spacer(1, 8))


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY VIEW
# ─────────────────────────────────────────────────────────────────────────────

def _add_history_view(elements: List, styles: Dict, trend_text: str) -> None:
    elements.append(Paragraph("<b>Entwicklung der Angriffsfläche</b>", styles["normal"]))
    elements.append(Spacer(1, 4))
    for line in trend_text.splitlines():
        if line.strip():
            elements.append(Paragraph(f"• {line.strip()}", styles["bullet"]))


# ─────────────────────────────────────────────────────────────────────────────
# INTERPRETATION TEXT
# ─────────────────────────────────────────────────────────────────────────────

def _build_interpretation(trend_table: Optional[Dict[str, Any]]) -> str:
    if not trend_table:
        return "Die Angriffsfläche ist stabil."

    worsening = []
    improving = []
    stable    = []

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
        return {
            "Öffentliche Ports": "öffentliche Dienste",
            "Kritische Services": "Administrationsdienste",
            "Hochrisiko-CVEs": "kritische Schwachstellen",
            "TLS-Schwächen": "Kryptokonfiguration",
        }.get(cat, cat)

    if worsening and not improving:
        cats = ", ".join(_label(c) for c, _ in worsening)
        if len(worsening) == 1 and worsening[0][0] == "TLS-Schwächen":
            return (
                "Die Angriffsfläche ist weitgehend stabil, zeigt jedoch eine Verschlechterung "
                "in der Kryptokonfiguration. TLS-Zertifikate und Cipher-Suites sollten zeitnah geprüft werden."
            )
        if len(worsening) == 1 and worsening[0][0] == "Hochrisiko-CVEs":
            return (
                f"Die Anzahl kritischer Schwachstellen ist um {worsening[0][1]} gestiegen. "
                "Patches werden zeitnah empfohlen."
            )
        return (
            f"Die Angriffsfläche zeigt eine Verschlechterung bei: {cats}. "
            "Handlungsempfehlungen beachten und Maßnahmen priorisieren."
        )

    if improving and not worsening:
        cats = ", ".join(_label(c) for c, _ in improving)
        return (
            f"Die Angriffsfläche hat sich verbessert, insbesondere bei: {cats}. "
            "Umgesetzte Maßnahmen zeigen Wirkung — dieser Trend sollte fortgesetzt werden."
        )

    if worsening and improving:
        worse  = ", ".join(_label(c) for c, _ in worsening)
        better = ", ".join(_label(c) for c, _ in improving)
        return (
            f"Gemischte Entwicklung: Verbesserung bei {better}, "
            f"Verschlechterung bei {worse}. Weitere Maßnahmen priorisieren."
        )

    return "Die Angriffsfläche ist stabil. Keine signifikanten Veränderungen zum Vormonat."


# ─────────────────────────────────────────────────────────────────────────────
# HILFSFUNKTIONEN
# ─────────────────────────────────────────────────────────────────────────────

def _tt_vals(trend_table: Optional[Dict], key: str) -> Tuple[int, int]:
    """Gibt (prev, curr) aus trend_table zurück, default (0, 0)."""
    if not trend_table or key not in trend_table:
        return 0, 0
    vals = trend_table[key]
    try:
        return int(vals[0]), int(vals[1])
    except Exception:
        return 0, 0


def _port_closed_label(trend_table: Optional[Dict]) -> str:
    """Versucht den Namen des geschlossenen Ports zu ermitteln."""
    return "geschlossen"


def _display_category_label(category: str) -> str:
    if category == "Kritische Services":
        return "Kritische Administrationsdienste"
    return str(category)


def _derive_trend_table(
    technical_json: Dict[str, Any],
    evaluation: Optional[Dict[str, Any]],
) -> Dict[str, Tuple[int, int, str]]:
    """Leitet Trend-Tabelle aus Snapshot-Daten ab."""

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
                    cid  = c.get("id") or c.get("cve") or ""
                    cvss = float(c.get("cvss") or 0)
                else:
                    cid  = str(c)
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
                    si   = s.get("ssl_info") or {}
                    port = s.get("port")
                    if si and (si.get("has_weak_cipher") or si.get("weaknesses") or si.get("issues")):
                        cnt += 1
                    if s.get("tls_weakness") or s.get("ssl_weakness"):
                        cnt += 1
                    if port in {443, 8443, 9443} and not si and not s.get("is_ssl"):
                        cnt += 1
                else:
                    si   = getattr(s, "ssl_info", None)
                    port = getattr(s, "port", None)
                    if si and (getattr(si, "has_weak_cipher", False) or getattr(si, "weaknesses", None)):
                        cnt += 1
                    if port in {443, 8443, 9443} and not si:
                        cnt += 1
            except Exception:
                continue
        return cnt

    current = {
        "Öffentliche Ports":  _count_open_ports(technical_json),
        "Kritische Services": _count_critical_services(technical_json),
        "Hochrisiko-CVEs":    _count_high_risk_cves(technical_json, evaluation),
        "TLS-Schwächen":      _count_tls_weaknesses(technical_json),
    }

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
                "Öffentliche Ports":  _count_open_ports(prev_source),
                "Kritische Services": _count_critical_services(prev_source),
                "Hochrisiko-CVEs":    _count_high_risk_cves(prev_source, None),
                "TLS-Schwächen":      _count_tls_weaknesses(prev_source),
            }
    else:
        prev = {k: 0 for k in current.keys()}

    trend_table = {}
    for k, curr in current.items():
        pv     = prev.get(k, 0)
        rating = _compute_rating(k, pv, curr)
        trend_table[k] = (pv, curr, rating)
    return trend_table


def _derive_chart_months(compare_month: Optional[str]) -> list:
    """
    Leitet die 6 Monats-Labels für den Chart ab.
    Der vorletzte Eintrag = compare_month, der letzte = aktueller Monat.
    Fallback: generische Labels.
    """
    import re

    month_num_map = {
        "jan":1,"feb":2,"mär":3,"mar":3,"apr":4,"mai":5,"may":5,"jun":6,
        "jul":7,"aug":8,"sep":9,"okt":10,"oct":10,"nov":11,"dez":12,"dec":12,
    }
    num_to_abbr = {
        1:"Jan",2:"Feb",3:"Mär",4:"Apr",5:"Mai",6:"Jun",
        7:"Jul",8:"Aug",9:"Sep",10:"Okt",11:"Nov",12:"Dez"
    }

    mon, year = None, None
    if compare_month:
        s = compare_month.strip()
        m = re.match(r"(\d{4})[-/](\d{1,2})", s)
        if m:
            year, mon = int(m.group(1)), int(m.group(2))
        else:
            parts = s.split()
            if len(parts) >= 2:
                try:
                    year = int(parts[-1])
                except ValueError:
                    pass
                for key, val in month_num_map.items():
                    if parts[0].lower().startswith(key):
                        mon = val
                        break

    if mon is None or year is None:
        return ["M-5", "M-4", "M-3", "M-2", "Vor", "Akt"]

    # Baue 6 Monate auf: 4 Monate vor compare_month, compare_month selbst, aktueller Monat
    result = []
    for offset in range(-4, 2):  # -4, -3, -2, -1, 0 (=compare), +1 (=aktuell)
        m_shifted = mon + offset
        y_shifted = year
        while m_shifted < 1:
            m_shifted += 12
            y_shifted -= 1
        while m_shifted > 12:
            m_shifted -= 12
            y_shifted += 1
        result.append(num_to_abbr[m_shifted])

    return result


def _format_month_label(month_str: str) -> str:
    """
    Normalisiert einen Monatsstring für den Tabellenheader.
    Eingaben wie 'März 2026', 'mar-2026', 'March 2026', '2026-03'
    werden zu 'MÄR 2026' normalisiert.
    Kein [:8]-Truncation mehr.
    """
    if not month_str:
        return "VORMONAT"

    month_map = {
        "jan": "JAN", "feb": "FEB", "mar": "MÄR", "mär": "MÄR", "märz": "MÄR",
        "apr": "APR", "mai": "MAI", "may": "MAI", "jun": "JUN",
        "jul": "JUL", "aug": "AUG", "sep": "SEP", "okt": "OKT", "oct": "OKT",
        "nov": "NOV", "dez": "DEZ", "dec": "DEZ",
    }

    s = month_str.strip()

    # Format "2026-03" oder "2026/03"
    import re
    m = re.match(r"(\d{4})[-/](\d{1,2})", s)
    if m:
        year = m.group(1)
        mon_num = int(m.group(2))
        num_to_abbr = {
            1:"JAN",2:"FEB",3:"MÄR",4:"APR",5:"MAI",6:"JUN",
            7:"JUL",8:"AUG",9:"SEP",10:"OKT",11:"NOV",12:"DEZ"
        }
        abbr = num_to_abbr.get(mon_num, str(mon_num))
        return f"{abbr} {year}"

    # Format "März 2026" oder "March 2026" oder "Mar 2026"
    parts = s.split()
    if len(parts) >= 2:
        mon_part = parts[0].lower()
        year_part = parts[-1]
        for key, val in month_map.items():
            if mon_part.startswith(key):
                return f"{val} {year_part}"
        # Fallback: ersten Teil kürzen auf 3 Zeichen
        return f"{parts[0][:3].upper()} {year_part}"

    # Nur ein Token — einfach uppercasen, maximal 8 Zeichen
    return s.upper()[:8]


def _next_month_label(compare_month: Optional[str]) -> str:
    """
    Leitet den aktuellen Monats-Label aus dem Vergleichsmonat ab
    (Vormonat + 1). Fallback: leerer String.
    """
    if not compare_month:
        return ""

    import re
    from datetime import date

    month_num_map = {
        "jan":1,"feb":2,"mär":3,"mar":3,"apr":4,"mai":5,"may":5,"jun":6,
        "jul":7,"aug":8,"sep":9,"okt":10,"oct":10,"nov":11,"dez":12,"dec":12,
    }
    num_to_abbr = {
        1:"Jan",2:"Feb",3:"Mär",4:"Apr",5:"Mai",6:"Jun",
        7:"Jul",8:"Aug",9:"Sep",10:"Okt",11:"Nov",12:"Dez"
    }

    s = compare_month.strip()

    # "2026-03"
    m = re.match(r"(\d{4})[-/](\d{1,2})", s)
    if m:
        year, mon = int(m.group(1)), int(m.group(2))
    else:
        parts = s.split()
        if len(parts) < 2:
            return ""
        mon_str = parts[0].lower()
        try:
            year = int(parts[-1])
        except ValueError:
            return ""
        mon = 0
        for key, val in month_num_map.items():
            if mon_str.startswith(key):
                mon = val
                break
        if mon == 0:
            return ""

    # +1 Monat
    if mon == 12:
        mon, year = 1, year + 1
    else:
        mon += 1

    return f"{num_to_abbr[mon]} {year}"


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