"""Tests für PDF Manager (Layout und Styling)."""

import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

from reportlab.platypus import Paragraph, Spacer
from reportlab.lib.styles import ParagraphStyle

from shodan_report.pdf.pdf_manager import prepare_pdf_elements
from shodan_report.evaluation.evaluation import Evaluation, RiskLevel  


class TestPDFManager:
    
    def setup_method(self):
        self.mock_evaluation = Evaluation(
            ip="192.168.1.1",
            risk=RiskLevel.MEDIUM,
            critical_points=[]
        )
        self.mock_business_risk = "medium"
    
    def test_prepare_pdf_elements_creates_all_sections(self):
        elements = prepare_pdf_elements(
            customer_name="Testkunde",
            month="2025-01",
            ip="192.168.1.1",
            management_text="Test Management Text",
            trend_text="Test Trend",
            technical_json={"open_ports": []},
            evaluation=self.mock_evaluation,       
            business_risk=self.mock_business_risk, 
            config={}
        )
        
        assert len(elements) > 0
        assert all(isinstance(elem, (Paragraph, Spacer)) for elem in elements)

    def test_styles_use_config_colors(self):
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
            evaluation=self.mock_evaluation,       
            business_risk=self.mock_business_risk, 
            config=config
        )
        
        header_text = str(elements[0])  # Erster Paragraph ist Header
        assert "#FF5733" in header_text or "FF5733" in header_text

    def test_technical_section_with_ports(self):
        """Testet den technischen Abschnitt mit Port-Informationen."""
        technical_json = {
            "open_ports": [
                {"port": 80, "product": "nginx", "version": "1.18"}, 
                {"port": 443, "product": "Apache", "version": "2.4"},
                {"port": 22, "product": "OpenSSH"}
            ]
        }
        
        elements = prepare_pdf_elements(
            customer_name="Test",
            month="2025-01",
            ip="1.1.1.1",
            management_text="",
            trend_text="",
            technical_json=technical_json,
            evaluation=self.mock_evaluation,       
            business_risk=self.mock_business_risk, 
            config={}
        )
        
        tech_section = [e for e in elements if "Technischer Anhang" in str(e)]
        assert len(tech_section) == 1

    def test_empty_trend_text(self):
        """Testet Verhalten bei leerem Trend-Text."""
        elements = prepare_pdf_elements(
            customer_name="Test",
            month="2025-01",
            ip="1.1.1.1",
            management_text="Management",
            trend_text="",  
            technical_json={"open_ports": []},
            evaluation=self.mock_evaluation,       
            business_risk=self.mock_business_risk, 
            config={}
        )
        

        trend_section = [e for e in elements if "Keine historischen Daten" in str(e)]
        assert len(trend_section) >= 1

    def test_missing_config(self):
        elements = prepare_pdf_elements(
            customer_name="Test",
            month="2025-01",
            ip="1.1.1.1",
            management_text="Test",
            trend_text="Test",
            technical_json={"open_ports": []},
            evaluation=self.mock_evaluation,       
            business_risk=self.mock_business_risk  
            # Kein config Parameter
        )
        
        assert len(elements) > 0  

    def test_management_text_multiline(self):
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
            evaluation=self.mock_evaluation,       
            business_risk=self.mock_business_risk, 
            config={}
        )

        management_paras = [e for e in elements if "Management-Zusammenfassung" in str(e)]
        assert len(management_paras) >= 1

    def test_footer_contains_timestamp(self):
        elements = prepare_pdf_elements(
            customer_name="Test",
            month="2025-01",
            ip="1.1.1.1",
            management_text="Test",
            trend_text="Test",
            technical_json={"open_ports": []},
            evaluation=self.mock_evaluation,       
            business_risk=self.mock_business_risk, 
            config={}
        )
        

        footer = str(elements[-1])
        current_date = datetime.now().strftime('%d.%m.%Y')
        assert current_date in footer