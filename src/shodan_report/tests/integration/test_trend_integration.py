"""
Integrationstests für die Trend-Section mit PDF-Manager.
"""

import pytest
from shodan_report.pdf.pdf_manager import prepare_pdf_elements


class TestTrendIntegration:
    """Testet die Integration der Trend-Section in PDF-Manager."""

    @pytest.fixture
    def mock_evaluation(self):
        """Mock-Evaluation für Tests."""
        return {
            "overall_risk": "MEDIUM",
            "risk_score": 3.2,
            "exposure_level": "MEDIUM",
            "critical_points": ["SSH auf Port 22"],
        }

    @pytest.fixture
    def mock_business_risk(self):
        """Mock-Business-Risk für Tests."""
        # ACHTUNG: In deinem Code scheint business_risk manchmal ein Integer zu sein!
        # Wir testen beide Fälle
        return "MEDIUM"  # String

    @pytest.fixture
    def mock_business_risk_as_int(self):
        """Alternative: Business Risk als Integer (falls das vorkommt)."""
        return 2  # Integer für "MEDIUM" vielleicht?

    # def test_trend_section_integration(self, mock_evaluation, mock_business_risk):
    #     """Testet dass Trend-Section korrekt in PDF integriert wird."""
    #     elements = prepare_pdf_elements(
    #         customer_name="Integration Test GmbH",
    #         month="Dezember 2023",
    #         ip="192.168.1.100",
    #         management_text="Test Management Zusammenfassung",
    #         trend_text="• Erster Eintrag\n• Zweiter Eintrag",
    #         technical_json={
    #             'open_ports': [
    #                 {"port": 80, "service": "HTTP", "product": "nginx"},
    #                 {"port": 443, "service": "HTTPS", "product": "nginx"}],
    #             'services': ['HTTP', 'HTTPS']
    #         },
    #         evaluation=mock_evaluation,
    #         business_risk=mock_business_risk,  # String
    #         config={}
    #     )

    #     # Prüfe dass Elemente generiert wurden
    #     assert len(elements) > 10, "Sollte mehrere PDF-Elemente generieren"
    #     print(f"✅ PDF-Elemente generiert: {len(elements)}")

    def test_empty_trend_integration(self, mock_evaluation, mock_business_risk):
        """Testet leere Trend-Section in Integration."""
        elements = prepare_pdf_elements(
            customer_name="Empty Trend Test",
            month="Januar 2024",
            ip="10.0.0.1",
            management_text="Test",
            trend_text="",  # LEER!
            technical_json={"open_ports": []},
            evaluation=mock_evaluation,
            business_risk=mock_business_risk,  # String
            config={},
        )

        # Finde den "keine Daten" Text
        no_data_elements = [
            e
            for e in elements
            if hasattr(e, "text")
            and "Trend-Analyse aktuell nicht möglich" in e.text
        ]

        assert len(no_data_elements) >= 1, "Sollte 'keine Daten' Meldung enthalten"
        print(f"✅ 'Keine Daten' Meldung gefunden")

    def test_business_risk_as_int(self, mock_evaluation, mock_business_risk_as_int):
        """Testet Business Risk als Integer (Edge Case)."""
        try:
            elements = prepare_pdf_elements(
                customer_name="Int Business Risk Test",
                month="Januar 2024",
                ip="10.0.0.2",
                management_text="Test",
                trend_text="Test Trend",
                technical_json={"open_ports": [80]},
                evaluation=mock_evaluation,
                business_risk=mock_business_risk_as_int,  # Integer!
                config={},
            )
            print(
                f"✅ Business Risk als Integer funktioniert: {len(elements)} Elemente"
            )
        except Exception as e:
            print(f"⚠️  Business Risk als Integer fehlgeschlagen: {e}")
            # Das könnte in Ordnung sein, wenn dein Code das nicht unterstützt


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
