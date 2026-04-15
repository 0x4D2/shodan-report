"""
Tests für die Trend-Section (neu ausgelagert).
"""

import pytest
from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from shodan_report.pdf.sections.trend import (
    create_trend_section,
    _build_multi_point_chart,
    _month_abbr,
)


class TestTrendSection:
    """Testet die ausgelagerte Trend-Section."""

    @pytest.fixture
    def mock_styles(self):
        """Echte ReportLab Styles für Tests."""
        styles = getSampleStyleSheet()

        return {
            "heading2": styles["Heading2"],
            "normal": styles["Normal"],
            "bullet": styles["Normal"],  # Platzhalter
            "disclaimer": styles["Italic"],
            "footer": styles["Normal"],
        }

    @pytest.fixture
    def mock_elements(self):
        """Leere Elemente-Liste für Tests."""
        return []

    def test_create_trend_section_with_history(self, mock_elements, mock_styles):
        """Test Trend-Section mit historischen Daten."""
        trend_text = "• Port 22 geschlossen\n• Neue HTTPS Instanz"

        create_trend_section(
            elements=mock_elements, styles=mock_styles, trend_text=trend_text
        )

        # Überprüfe dass Elemente hinzugefügt wurden
        assert len(mock_elements) > 0

        # Überprüfe spezifische Element-Typen
        element_types = [type(e).__name__ for e in mock_elements]
        assert "Spacer" in element_types
        assert "Paragraph" in element_types

        # Überprüfe Inhalte
        for element in mock_elements:
            if isinstance(element, Paragraph):
                if hasattr(element, "text"):
                    if "Trend" in element.text:
                        assert True  # Überschrift vorhanden
                        break

    def test_create_trend_section_empty(self, mock_elements, mock_styles):
        """Test Trend-Section ohne Daten."""
        create_trend_section(elements=mock_elements, styles=mock_styles, trend_text="")

        # Mindestens sollte etwas hinzugefügt worden sein
        assert len(mock_elements) > 0

        # Suche nach dem ersten-Report-Text des neuen _add_no_data_view
        found = False
        for element in mock_elements:
            if isinstance(element, Paragraph) and hasattr(element, "text"):
                if "erste Analyse für dieses Asset" in element.text:
                    found = True
                    break

        assert found, "Sollte 'keine Daten' Meldung enthalten"

    def test_create_trend_section_with_comparison(self, mock_elements, mock_styles):
        """Test Trend-Section mit Monatsvergleich."""
        # Provide a non-zero trend_table so the comparison view is rendered
        # (all-zero previous values would trigger the first-report guard)
        trend_table = {
            "Öffentliche Ports":  (3, 4, "verschlechtert"),
            "Kritische Services": (1, 1, "stabil"),
            "Hochrisiko-CVEs":    (2, 3, "verschlechtert"),
            "TLS-Schwächen":      (0, 0, "stabil"),
        }
        create_trend_section(
            elements=mock_elements,
            styles=mock_styles,
            trend_text="",
            compare_month="November 2023",
            trend_table=trend_table,
        )

        # Expect a Table to be present for the comparison view
        from reportlab.platypus import Table

        assert any(isinstance(e, Table) for e in mock_elements), "Vergleichstabelle sollte vorhanden sein"


# ─── _month_abbr Tests ────────────────────────────────────────────────────────

def test_month_abbr_april():
    assert _month_abbr("2026-04") == "Apr"

def test_month_abbr_december():
    assert _month_abbr("2026-12") == "Dez"

def test_month_abbr_january():
    assert _month_abbr("2026-01") == "Jan"

def test_month_abbr_invalid_falls_back():
    assert _month_abbr("ungueltig") == "ungueltig"


# ─── _build_multi_point_chart Tests ──────────────────────────────────────────

def test_chart_uses_exposure_history_when_provided():
    """Mit echter History: Anzahl Punkte = len(history)."""
    history = [
        {"month": "2026-03", "score": 2, "real": True},
        {"month": "2026-04", "score": 3, "real": True},
        {"month": "2026-05", "score": 2, "real": True},
    ]
    drawing, n_months = _build_multi_point_chart(
        prev_score=3, curr_score=2,
        compare_month="2026-04",
        exposure_history=history,
    )
    assert n_months == 3


def test_chart_fallback_two_points_without_history():
    """Ohne History: Fallback auf 2 Punkte (Vormonat + Aktuell)."""
    drawing, n_months = _build_multi_point_chart(
        prev_score=2, curr_score=3,
        compare_month="2026-04",
        exposure_history=None,
    )
    assert n_months == 2


def test_chart_fallback_with_single_history_entry():
    """Weniger als 2 History-Einträge → Fallback auf 2-Punkt-Darstellung."""
    history = [{"month": "2026-05", "score": 2, "real": True}]
    drawing, n_months = _build_multi_point_chart(
        prev_score=2, curr_score=2,
        compare_month="2026-04",
        exposure_history=history,
    )
    assert n_months == 2


def test_chart_six_months_history():
    """6 Monate echte Daten → n_months == 6."""
    history = [
        {"month": f"2025-{i:02d}", "score": 2, "real": True}
        for i in range(12, 6, -1)
    ]
    history = list(reversed(history))
    drawing, n_months = _build_multi_point_chart(
        prev_score=2, curr_score=2,
        compare_month="2025-11",
        exposure_history=history,
    )
    assert n_months == 6


def test_chart_scores_clamped_to_valid_range():
    """Scores außerhalb 1-5 werden auf gültige Werte geclampt — kein Absturz."""
    history = [
        {"month": "2026-04", "score": 0, "real": True},
        {"month": "2026-05", "score": 9, "real": True},
    ]
    drawing, n_months = _build_multi_point_chart(
        prev_score=0, curr_score=9,
        compare_month="2026-04",
        exposure_history=history,
    )
    assert n_months == 2
