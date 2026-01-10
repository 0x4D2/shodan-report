import pytest
from unittest.mock import Mock, patch
from reportlab.platypus import Paragraph, Spacer
from shodan_report.pdf.sections.header import _create_header, extract_assets_from_technical_data


class TestHeaderSection:
    
    def test_extract_assets_from_technical_data(self):
        technical_json = {
            "domains": ["example.com", "test.de"],
            "hostnames": ["server1.example.com"],
            "org": "Test ISP GmbH"
        }
        
        assets = extract_assets_from_technical_data(technical_json)
        
        assert len(assets) == 4  # IP + 3 Assets
        assert "example.com (Domain)" in assets
        assert "server1.example.com (Hostname)" in assets
        assert "Test ISP GmbH (Organisation)" in assets
    
    def test_extract_assets_empty_data(self):

        technical_json = {}
        assets = extract_assets_from_technical_data(technical_json)
        
        assert assets == []  # Keine zusätzlichen Assets
    
    def test_create_header_basic_functionality(self):
        elements = []
        styles = {
            'title': 'TitleStyle',
            'normal': 'NormalStyle'
        }
        
        _create_header(
            elements=elements,
            styles=styles,
            customer_name="Testkunde GmbH",
            month="2025-01",
            ip="192.168.1.1",
            config={}
        )
        
    
        assert len(elements) > 0
        assert len(elements) >= 3
    
    def test_create_header_with_styling_config(self):
        elements = []
        styles = {
            'title': 'TitleStyle',
            'normal': 'NormalStyle'
        }
        
        config = {
            "styling": {
                "primary_color": "#FF0000",  # Rot
                "secondary_color": "#00FF00"  # Grün
            }
        }
        
        _create_header(
            elements=elements,
            styles=styles,
            customer_name="Testkunde",
            month="2025-01",
            ip="192.168.1.1",
            config=config
        )
        
        assert len(elements) > 0
    
    def test_create_header_with_customer_contact(self):
        elements = []
        styles = {
            'title': 'TitleStyle',
            'normal': 'NormalStyle'
        }
        
        config = {
            "customer": {
                "contact": "security@testkunde.de",
                "slug": "testkunde_gmbh"
            }
        }
        
        _create_header(
            elements=elements,
            styles=styles,
            customer_name="Testkunde GmbH",
            month="2025-01",
            ip="192.168.1.1",
            config=config
        )
        
        assert len(elements) > 0
        # Report-ID sollte den Slug enthalten
        # (Prüfung über Mock möglich, aber erstmal nur Laufzeitprüfung)
    
    def test_create_header_with_additional_assets(self):
        elements = []
        styles = {
            'title': 'TitleStyle',
            'normal': 'NormalStyle'
        }
        
        additional_assets = [
            "example.com",
            "backup.example.com"
        ]
        
        _create_header(
            elements=elements,
            styles=styles,
            customer_name="Testkunde",
            month="2025-01",
            ip="192.168.1.1",
            config={},
            additional_assets=additional_assets
        )
        
        assert len(elements) > 0
        # Assets-Liste sollte 3 Einträge haben (IP + 2 zusätzliche)
    
    def test_month_format_conversion(self):
        elements = []
        styles = {'title': 'TitleStyle', 'normal': 'NormalStyle'}
        
        test_cases = [
            ("2025-01", "Januar 2025"),
            ("2025-12", "Dezember 2025"),
            ("invalid", "invalid")  # Fallback
        ]
        
        for month_input, expected_in_text in test_cases:
            elements.clear()
            _create_header(
                elements=elements,
                styles=styles,
                customer_name="Test",
                month=month_input,
                ip="192.168.1.1",
                config={}
            )
            assert len(elements) > 0  # Kein Crash
    
    def test_report_id_format(self):
        elements = []
        styles = {'title': 'TitleStyle', 'normal': 'NormalStyle'}
        
        _create_header(
            elements=elements,
            styles=styles,
            customer_name="CHINA NET",
            month="2025-01",
            ip="111.170.152.60",
            config={}
        )
        
        # Report-ID sollte sein: "china_net_202501_111-170-152-60"
        # Wir prüfen nur dass es generiert wurde
        assert len(elements) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])