# src/shodan_report/tests/pdf/sections/test_management.py
"""Tests für die Management-Zusammenfassung (neue Struktur)."""

import pytest
from reportlab.platypus import Paragraph, Table
from shodan_report.pdf.styles import create_styles, create_theme
from shodan_report.pdf.sections.management import create_management_section
from shodan_report.models import Service
from shodan_report.evaluation import Evaluation

# Dummy-Helfer, falls nicht verfügbar
def make_service(port, product="TestProduct", vpn=False, tunneled=False, cert=False, ssl_info=None):
    return Service(
        port=port,
        transport="tcp",
        product=product,
        ssl_info=ssl_info,
        vpn_protected=vpn,
        tunneled=tunneled,
        cert_required=cert,
        raw={}
    )

class TestManagementSection:

    @pytest.fixture
    def styles(self):
        theme = create_theme("#1a365d", "#2d3748")
        return create_styles(theme)
    
    # ────────────────────────────────
    # 1. Grundlegende Erstellung
    # ────────────────────────────────
    def test_basic_paragraphs_created(self, styles):
        elements = []
        evaluation = Evaluation(ip="192.168.1.1", risk="LOW", critical_points=[])
        technical_json = {
            "open_ports": [
                {"port": 22, "product": "OpenSSH"},
                {"port": 80, "product": "nginx"}
            ]
        }

        create_management_section(
            elements=elements,
            styles=styles,
            management_text="Externe Angriffsfläche stabil.",
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk="LOW"
        )

        assert len(elements) > 0
        assert any(isinstance(e, Paragraph) for e in elements)
        assert any(isinstance(e, Table) for e in elements)  # Exposure-Tabelle

    # ────────────────────────────────
    # 2. Leere Daten
    # ────────────────────────────────
    def test_empty_management_text_and_ports(self, styles):
        elements = []
        evaluation = Evaluation(ip="10.0.0.1", risk="LOW", critical_points=[])
        technical_json = {}

        create_management_section(
            elements=elements,
            styles=styles,
            management_text="",
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk="LOW"
        )

        assert len(elements) > 0
        assert any(isinstance(e, (Paragraph, Table)) for e in elements)


    # ────────────────────────────────
    # 3. Kritische CVEs & strukturelle Risiken
    # ────────────────────────────────
    def test_critical_cves_and_structural_risks(self, styles):
        elements = []
        evaluation = Evaluation(ip="1.1.1.1", risk="HIGH", critical_points=[])

        s1 = make_service(22)  # kritische CVE
        s1.version_risk = 1

        s2 = make_service(80, ssl_info=None)  # unsicher

        services = [s1, s2]

        create_management_section(
            elements=elements,
            styles=styles,
            management_text="",
            technical_json={"open_ports": services},
            evaluation=evaluation,
            business_risk="HIGH"
        )

        # Prüfen, dass strukturelle Risiken erkannt wurden
        assert any("strukturelle Risiken" in str(e) for e in elements)

    def test_management_section_basic(self):
        """Minimaler Test, prüft, dass Elemente erstellt werden."""
        elements = []
        theme = create_theme("#1a365d", "#2d3748")
        styles = create_styles(theme)

        management_text = "Externe Angriffsfläche stabil. 2 öffentliche Dienste."
        technical_json = {
            "open_ports": [
                {"port": 22, "product": "OpenSSH"},
                {"port": 80, "product": "nginx"}
            ]
        }
        evaluation = Evaluation(
            ip="192.168.1.1",
            risk="LOW",
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
        assert any(isinstance(e, Paragraph) for e in elements)

    # ────────────────────────────────
    # 4. Insights-Limitierung
    # ────────────────────────────────
    def test_insights_and_recommendations_generated(self, styles):
        elements = []
        evaluation = Evaluation(ip="1.1.1.1", risk="MEDIUM", critical_points=[])
        services = [make_service(p) for p in range(1, 10)]  # viele Services
        technical_json = {"open_ports": [s.raw for s in services]}

        create_management_section(
            elements=elements,
            styles=styles,
            management_text="Test Insights",
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk="MEDIUM"
        )

        bullets = [e for e in elements if isinstance(e, Paragraph) and e.style.name == "Bullet"]
        assert len(bullets) > 0  # Es gibt Insights & Empfehlungen
        # Optional: Max 4 Insights, max 3 Empfehlungen? → abhängig von generate_priority_*
        # Wenn die Helper limitiert sind, könnte man das hier prüfen

    # ────────────────────────────────
    # 5. Evaluation als dict
    # ────────────────────────────────
    def test_evaluation_dict_conversion(self, styles):
        elements = []
        evaluation_dict = {"ip": "1.2.3.4", "risk": "LOW", "critical_points": []}
        technical_json = {}

        create_management_section(
            elements=elements,
            styles=styles,
            management_text="Test dict evaluation",
            technical_json=technical_json,
            evaluation=evaluation_dict,
            business_risk="LOW"
        )

        assert len(elements) > 0
    
    # ────────────────────────────────
    # 6. VPN, Tunnel, cert_flags
    # ────────────────────────────────
    def test_services_with_security_flags(self, styles):
        elements = []
        evaluation = Evaluation(ip="5.6.7.8", risk="MEDIUM", critical_points=[])
        services = [
            make_service(22, vpn=True),
            make_service(443, tunneled=True, ssl_info={"protocol": "TLSv1.3"}, cert=True)
        ]
        technical_json = {"open_ports": [s.raw for s in services]}

        create_management_section(
            elements=elements,
            styles=styles,
            management_text="Test Flags",
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk="MEDIUM"
        )

        paragraph_texts = [str(e.getPlainText()) for e in elements if isinstance(e, Paragraph)]
        assert any("Dienste identifiziert" in t for t in paragraph_texts)

    def test_management_section_with_realistic_services(self):
        """Testet generierte Insights bei gemischten Services."""
        elements = []
        theme = create_theme("#1a365d", "#2d3748")
        styles = create_styles(theme)

        management_text = "Test der externen Angriffsfläche mit realistischen Services."
        technical_json = {
            "open_ports": [
                {"port": 22, "product": "OpenSSH"},
                {"port": 80, "product": "nginx", "ssl_info": None},
                {"port": 443, "product": "nginx", "ssl_info": {"protocol": "TLSv1.3"}}
            ]
        }
        evaluation = Evaluation(
            ip="10.0.0.1",
            risk="MEDIUM",
            critical_points=["SSH auf Port 22 öffentlich"]
        )
        business_risk = "MEDIUM"

        create_management_section(
            elements=elements,
            styles=styles,
            management_text=management_text,
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk=business_risk,
            config={}
        )

        assert any(isinstance(e, Paragraph) for e in elements)

        table_found = any(str(getattr(e, "_cellvalues", None)) for e in elements)
        assert table_found

    def test_management_section_empty_data(self):
        """Testet Verhalten bei leeren technischen Daten."""
        elements = []
        theme = create_theme("#1a365d", "#2d3748")
        styles = create_styles(theme)

        management_text = "Keine offenen Dienste."
        technical_json = {}
        evaluation = Evaluation(
            ip="10.0.0.1",
            risk="LOW",
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
        # Es sollten trotzdem wichtige Absätze erstellt werden
        assert any(isinstance(e, Paragraph) for e in elements)

