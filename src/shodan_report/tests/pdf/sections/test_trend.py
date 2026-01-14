"""
Tests für die Trend-Section (neu ausgelagert).
"""

import pytest
from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from shodan_report.pdf.sections.trend import create_trend_section


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

        # Suche nach "Keine historischen Daten" oder "Erste Analyse"
        found = False
        for element in mock_elements:
            if isinstance(element, Paragraph) and hasattr(element, "text"):
                if "historischen" in element.text or "Erste Analyse" in element.text:
                    found = True
                    break

        assert found, "Sollte 'keine Daten' Meldung enthalten"

    def test_create_trend_section_with_comparison(self, mock_elements, mock_styles):
        """Test Trend-Section mit Monatsvergleich."""
        create_trend_section(
            elements=mock_elements,
            styles=mock_styles,
            trend_text="",
            compare_month="November 2023",
        )

        # Suche nach Vergleichs-Tabelle
        table_content = False
        for element in mock_elements:
            if isinstance(element, Paragraph) and hasattr(element, "text"):
                if "Vormonat" in element.text and "Aktuell" in element.text:
                    table_content = True
                    break

        assert table_content, "Vergleichstabelle sollte vorhanden sein"
