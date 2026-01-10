# src/shodan_report/tests/pdf/sections/test_management.py
"""Tests für die Management-Zusammenfassung."""

import pytest
from reportlab.platypus import Paragraph, Spacer
from shodan_report.pdf.styles import _create_styles
from shodan_report.pdf.sections.management import (
    create_management_section,
    _generate_insights,
    _generate_recommendations
)

from shodan_report.evaluation.evaluation import Evaluation, RiskLevel


class TestManagementSection:
    
    def test_management_section_with_minimal_data(self):
        elements = []
        styles = _create_styles("#1a365d", "#2d3748") 
        
        management_text = "Externe Angriffsfläche stabil. 2 öffentliche Dienste."
        technical_json = {
            "open_ports": [
                {"port": 22, "product": "OpenSSH"},  
                {"port": 80, "product": "nginx"}
            ]
        }
        
        
        evaluation = Evaluation(
            ip="192.168.1.1",  
            risk=RiskLevel.LOW,
            critical_points=[]
        )
        business_risk = "LOW"
        
        create_management_section(
            elements=elements,
            styles=styles,
            management_text=management_text,
            technical_json=technical_json,
            evaluation=evaluation,         
            business_risk=business_risk,
            config={}
        )
        
        assert len(elements) > 0
        assert any(isinstance(elem, Paragraph) for elem in elements)
    
    def test_generate_insights_with_open_ports(self):
        technical_json = {
            "open_ports": [
                {"port": 22, "product": "OpenSSH"},  
                {"port": 80, "product": "nginx"}
            ]
        }

        evaluation = Evaluation(
            ip="192.168.1.1",
            risk=RiskLevel.LOW,
            critical_points=[]
        )
        business_risk = "LOW"
        
        insights = _generate_insights(technical_json, evaluation, business_risk)
        
        assert len(insights) > 0
        assert any("2 öffentliche Dienste" in insight for insight in insights)
    
    def test_generate_insights_empty_data(self):
        technical_json = {}

        evaluation = Evaluation(
            ip="192.168.1.1",
            risk=RiskLevel.LOW,
            critical_points=[]
        )
        business_risk = "LOW"
        
        insights = _generate_insights(technical_json, evaluation, business_risk)
        
        assert len(insights) > 0
    
    def test_generate_recommendations_by_risk_level(self):
        test_cases = [
            ("CRITICAL", "Notfallmaßnahmen"),
            ("HIGH", "Priorisierte Maßnahmen"),
            ("MEDIUM", "Geplante Maßnahmen"),
            ("LOW", "sofortigen Notfallmaßnahmen"),
        ]
        
        for risk_level, expected_keyword in test_cases:
            technical_json = {"open_ports": []}
            evaluation = Evaluation(
                ip="192.168.1.1",
                risk=RiskLevel.LOW,  # Beliebiger Wert für Test
                critical_points=[]
            )
            
            recommendations = _generate_recommendations(risk_level, technical_json, evaluation)
            
            assert len(recommendations) > 0, f"Keine Empfehlungen für {risk_level}"
            assert any(expected_keyword in rec for rec in recommendations), \
                f"Keyword '{expected_keyword}' nicht gefunden in: {recommendations}"
    
    def test_generate_recommendations_with_specific_services(self):
        business_risk = "MEDIUM"
        technical_json = {
            "open_ports": [
                {"port": 22, "product": "OpenSSH"},
                {"port": 80, "product": "nginx"},
                {"port": 3306, "product": "MySQL"}
            ]
        }
        evaluation = Evaluation(
            ip="192.168.1.1",
            risk=RiskLevel.MEDIUM,
            critical_points=["SSH auf Port 22 öffentlich"]
        )
        
        recommendations = _generate_recommendations(business_risk, technical_json, evaluation)
        
        assert len(recommendations) > 0
        ssh_found = any("SSH" in rec for rec in recommendations)
        web_found = any("Webserver" in rec or "TLS" in rec for rec in recommendations)
        mysql_found = any("MySQL" in rec for rec in recommendations)
        
        assert ssh_found or web_found or mysql_found


if __name__ == "__main__":
    pytest.main([__file__, "-v"])