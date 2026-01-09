"""Tests für PDF Manager (Layout und Styling)."""

import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

# ReportLab Imports für die Tests
from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import ParagraphStyle

from shodan_report.pdf.pdf_manager import prepare_pdf_elements


class TestPDFManager:
    """Test-Klasse für PDF Manager."""
    def test_prepare_pdf_elements_creates_all_sections(self):
        """Testet ob alle PDF-Sektionen erstellt werden."""
        elements = prepare_pdf_elements(
            customer_name="Testkunde",
            month="2025-01",
            ip="192.168.1.1",
            management_text="Test Management Text",
            trend_text="Test Trend",
            technical_json={"open_ports": []},
            config={}
        )
        
        assert len(elements) > 0
        assert all(isinstance(elem, (Paragraph, Spacer)) for elem in elements)

    def test_styles_use_config_colors(self):
        """Testet ob Farben aus der Config korrekt übernommen werden."""
        config = {
            "styling": {
                "primary_color": "#FF5733",
                "secondary_color": "#33FF57"
            }
        }
        
        elements = prepare_pdf_elements(
            customer_name="Test",
            month="2025-01",
            ip="1.1.1.1",
            management_text="Test",
            trend_text="Test",
            technical_json={"open_ports": []},
            config=config
        )
        
        # Überprüfe ob primäre Farbe im Header verwendet wird
        header_text = str(elements[0])  # Erster Paragraph ist Header
        assert "#FF5733" in header_text or "FF5733" in header_text

    def test_technical_section_with_ports(self):
        """Testet den technischen Abschnitt mit Port-Informationen."""
        technical_json = {
            "open_ports": [
                {"port": 80, "service": {"product": "nginx", "version": "1.18"}},
                {"port": 443, "service": {"product": "Apache", "version": "2.4"}},
                {"port": 22, "service": {"product": "OpenSSH"}}
            ]
        }
        
        elements = prepare_pdf_elements(
            customer_name="Test",
            month="2025-01",
            ip="1.1.1.1",
            management_text="",
            trend_text="",
            technical_json=technical_json,
            config={}
        )
        
        # Finde technischen Abschnitt
        tech_section = [e for e in elements if "Technischer Anhang" in str(e)]
        assert len(tech_section) == 1

    def test_empty_trend_text(self):
        """Testet Verhalten bei leerem Trend-Text."""
        elements = prepare_pdf_elements(
            customer_name="Test",
            month="2025-01",
            ip="1.1.1.1",
            management_text="Management",
            trend_text="",  # Leerer Trend
            technical_json={"open_ports": []},
            config={}
        )
        
        # Sollte Standard-Text anzeigen
        trend_section = [e for e in elements if "Keine historischen Daten" in str(e)]
        assert len(trend_section) >= 1


    def test_missing_config(self):
        """Testet Default-Verhalten ohne Config."""
        elements = prepare_pdf_elements(
            customer_name="Test",
            month="2025-01",
            ip="1.1.1.1",
            management_text="Test",
            trend_text="Test",
            technical_json={"open_ports": []}
            # Kein config Parameter
        )
        
        assert len(elements) > 0  # Sollte trotzdem funktionieren

    def test_management_text_multiline(self):
        """Testet mehrzeiligen Management-Text."""
        multiline_text = """Erste Zeile
        Zweite Zeile
        Dritte Zeile"""
        
        elements = prepare_pdf_elements(
            customer_name="Test",
            month="2025-01",
            ip="1.1.1.1",
            management_text=multiline_text,
            trend_text="",
            technical_json={"open_ports": []},
            config={}
        )
        
        # Zähle Paragraphs im Management-Bereich
        management_paras = [e for e in elements if "Management-Zusammenfassung" in str(e)]
        assert len(management_paras) >= 1
        

    def test_footer_contains_timestamp(self):
        """Testet ob Footer korrekten Zeitstempel enthält."""
        from datetime import datetime
        
        elements = prepare_pdf_elements(
            customer_name="Test",
            month="2025-01",
            ip="1.1.1.1",
            management_text="Test",
            trend_text="Test",
            technical_json={"open_ports": []},
            config={}
        )
        
        # Letztes Element ist Footer
        footer = str(elements[-1])
        current_date = datetime.now().strftime('%d.%m.%Y')
        assert current_date in footer