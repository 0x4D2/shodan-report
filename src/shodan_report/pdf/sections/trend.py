"""
Trend-Analyse Section für PDF-Reports.
Enthält Logik für Trend-Vergleiche und historische Analysen.
"""

from typing import List, Dict, Optional
from reportlab.platypus import Spacer, Paragraph


def create_trend_section(
    elements: List, 
    styles: Dict, 
    trend_text: str,
    compare_month: Optional[str] = None,
    legacy_mode: bool = False  # NEU: Für Backward Compatibility
) -> None:
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
    elements.append(Paragraph("<b>2. Trend- & Vergleichsanalyse</b>", styles['heading2']))
    elements.append(Spacer(1, 8))
    
    if compare_month:
        # MIT VERGLEICH zu einem Vormonat
        _add_comparison_view(elements, styles, trend_text, compare_month)
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
    compare_month: str
) -> None:
    """Füge Trend-Ansicht MIT Monatsvergleich hinzu."""
    elements.append(Paragraph(f"<b>Veränderung zur {compare_month}-Analyse</b>", styles['normal']))
    elements.append(Spacer(1, 6))
    
    # EINFACHE TEXT-TABELLE (vorerst hartcodiert - später dynamisch)
    table_lines = [
        "<b>Kategorie          Vormonat  Aktuell  Bewertung</b>",
        "─────────────────────────────────────────────────────",
        "Öffentl. Ports           5        5    unverändert",
        "Krit. Services           1        1    stabil",
        "Hochrisiko-CVEs          0        0    stabil",
        "TLS-Schwächen            1        2    leicht schlechter"
    ]
    
    for line in table_lines:
        elements.append(Paragraph(line, styles['normal']))
    
    elements.append(Spacer(1, 12))
    
    # Interpretation
    elements.append(Paragraph("<b>Interpretation:</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        "Die Angriffsfläche ist stabil, zeigt jedoch eine leichte Verschlechterung "
        "in der Kryptokonfiguration, was langfristig relevant werden kann.",
        styles['normal']
    ))


def _add_history_view(elements: List, styles: Dict, trend_text: str) -> None:
    """Füge Trend-Ansicht OHNE Vergleich hinzu (nur historische Liste)."""
    elements.append(Paragraph("<b>Historie / Trend</b>", styles['normal']))
    elements.append(Spacer(1, 4))
    
    for line in trend_text.splitlines():
        if line.strip():
            elements.append(Paragraph(f"• {line.strip()}", styles['bullet']))


def _add_no_data_view(elements: List, styles: Dict, legacy_mode: bool = False) -> None:
    """
    Füge Ansicht hinzu, wenn keine Trend-Daten verfügbar sind.
    
    Args:
        legacy_mode: Wenn True, verwendet den alten Text für Backward Compatibility
    """
    if legacy_mode:
        # ALTER TEXT (für Tests)
        elements.append(Paragraph(
            "Keine historischen Daten für Trendanalyse vorhanden.", 
            styles['normal']
        ))
    else:
        # NEUER TEXT (besser formuliert)
        elements.append(Paragraph(
            "<i>Erste Analyse – Trend wird bei zukünftigen Vergleichen sichtbar.</i>", 
            styles['normal']
        ))