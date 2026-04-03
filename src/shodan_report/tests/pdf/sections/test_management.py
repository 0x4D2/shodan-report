# src/shodan_report/tests/pdf/sections/test_management.py
"""Tests für die Management-Zusammenfassung (neue Struktur)."""

import pytest
from reportlab.platypus import Paragraph, Table
from reportlab.lib.units import mm
from shodan_report.pdf.styles import create_styles, create_theme
from shodan_report.pdf.sections.management import (
    create_management_section,
    _kpi_cell,
    _KPI_CELL_W,
)
from shodan_report.models import Service
from shodan_report.evaluation import Evaluation


# Dummy-Helfer, falls nicht verfügbar
def make_service(
    port, product="TestProduct", vpn=False, tunneled=False, cert=False, ssl_info=None
):
    return Service(
        port=port,
        transport="tcp",
        product=product,
        ssl_info=ssl_info,
        vpn_protected=vpn,
        tunneled=tunneled,
        cert_required=cert,
        raw={},
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
                {"port": 80, "product": "nginx"},
            ]
        }

        create_management_section(
            elements=elements,
            styles=styles,
            management_text="Externe Angriffsfläche stabil.",
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk="LOW",
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
            business_risk="LOW",
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
            business_risk="HIGH",
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
                {"port": 80, "product": "nginx"},
            ]
        }
        evaluation = Evaluation(ip="192.168.1.1", risk="LOW", critical_points=[])
        business_risk = "LOW"

        create_management_section(
            elements=elements,
            styles=styles,
            management_text=management_text,
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk=business_risk,
            config={},
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
            business_risk="MEDIUM",
        )

        bullets = [
            e for e in elements if isinstance(e, Paragraph) and e.style.name == "Bullet"
        ]
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
            business_risk="LOW",
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
            make_service(
                443, tunneled=True, ssl_info={"protocol": "TLSv1.3"}, cert=True
            ),
        ]
        technical_json = {"open_ports": [s.raw for s in services]}

        create_management_section(
            elements=elements,
            styles=styles,
            management_text="Test Flags",
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk="MEDIUM",
        )

        paragraph_texts = [
            str(e.getPlainText()) for e in elements if isinstance(e, Paragraph)
        ]
        assert any("Dienste" in t or "Angriffsfläche" in t for t in paragraph_texts)

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
                {"port": 443, "product": "nginx", "ssl_info": {"protocol": "TLSv1.3"}},
            ]
        }
        evaluation = Evaluation(
            ip="10.0.0.1", risk="MEDIUM", critical_points=["SSH auf Port 22 öffentlich"]
        )
        business_risk = "MEDIUM"

        create_management_section(
            elements=elements,
            styles=styles,
            management_text=management_text,
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk=business_risk,
            config={},
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
        evaluation = Evaluation(ip="10.0.0.1", risk="LOW", critical_points=[])
        business_risk = "LOW"

        create_management_section(
            elements=elements,
            styles=styles,
            management_text=management_text,
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk=business_risk,
            config={},
        )

        assert len(elements) > 0
        # Es sollten trotzdem wichtige Absätze erstellt werden
        assert any(isinstance(e, Paragraph) for e in elements)

    def test_management_text_is_rendered_in_elements(self, styles):
        """management_text wird tatsächlich in die PDF-Elemente gerendert (30.03.2026)."""
        elements = []
        evaluation = Evaluation(ip="10.0.0.1", risk="MEDIUM", critical_points=[])
        technical_json = {"open_ports": [{"port": 443, "product": "nginx"}]}
        management_text = "Empfehlung: RDP-Zugang sofort schließen."

        create_management_section(
            elements=elements,
            styles=styles,
            management_text=management_text,
            technical_json=technical_json,
            evaluation=evaluation,
            business_risk="MEDIUM",
            config={},
        )

        para_texts = []
        for e in elements:
            if isinstance(e, Paragraph) and hasattr(e, "text"):
                try:
                    para_texts.append(e.getPlainText())
                except Exception:
                    para_texts.append(str(e.text))

        found = any("RDP-Zugang sofort schließen" in t for t in para_texts)
        assert found, "management_text-Inhalt muss in den gerenderten Elementen erscheinen"


# ──────────────────────────────────────────────────────────────────────────────
# KPI-Karten: unit- und integrations-Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestKpiCell:
    """Unit-Tests für die _kpi_cell()-Hilfsfunktion."""

    def test_returns_table(self):
        cell = _kpi_cell("Label", "42")
        assert isinstance(cell, Table)

    def test_column_width_matches_constant(self):
        cell = _kpi_cell("Label", "42")
        # colWidths ist eine Liste mit genau einem Eintrag
        assert len(cell._colWidths) == 1
        assert abs(cell._colWidths[0] - _KPI_CELL_W * mm) < 0.01

    def test_contains_label_and_value_paragraphs(self):
        cell = _kpi_cell("Offene Ports", "7")
        texts = []
        for row in cell._cellvalues:
            for item in row:
                if isinstance(item, Paragraph):
                    texts.append(item.getPlainText())
        assert any("Offene Ports" in t for t in texts)
        assert any("7" in t for t in texts)

    def test_default_value_color_neutral(self):
        """Ohne explizite Farbe darf der Wert-Paragraph nicht rot sein."""
        from shodan_report.pdf.styles import Colors
        cell = _kpi_cell("CVEs gesamt", "0")
        val_para = cell._cellvalues[1][0]
        assert isinstance(val_para, Paragraph)
        assert val_para.style.textColor == Colors.text

    def test_critical_color_applied(self):
        """Mit risk_critical_dot als Farbe muss der Wert-Paragraph diese Farbe tragen."""
        from shodan_report.pdf.styles import Colors
        cell = _kpi_cell("Kritisch (≥9)", "3", Colors.risk_critical_dot)
        val_para = cell._cellvalues[1][0]
        assert val_para.style.textColor == Colors.risk_critical_dot

    def test_background_uses_design_system_color(self):
        """Hintergrundfarbe der Karte stammt aus Colors.bg_light."""
        from shodan_report.pdf.styles import Colors
        cell = _kpi_cell("Test", "1")
        # _bkgrndcmds stores ('BACKGROUND', start, stop, color) tuples after setStyle()
        colors_found = [cmd[3] for cmd in cell._bkgrndcmds]
        assert Colors.bg_light in colors_found, (
            f"Expected Colors.bg_light ({Colors.bg_light}) in background commands, got {colors_found}"
        )


class TestKpiRowInSection:
    """Integrations-Tests: KPI-Zeile im generierten Section-Output."""

    @pytest.fixture
    def styles(self):
        return create_styles(create_theme("#1a365d", "#2d3748"))

    def _run(self, styles, technical_json, cves=None):
        """Erzeugt die Management-Section und gibt die Elemente zurück."""
        eval_obj = {"ip": "1.2.3.4", "risk": "MEDIUM", "critical_points": [], "cves": cves or []}
        elements = []
        create_management_section(
            elements=elements,
            styles=styles,
            management_text="",
            technical_json=technical_json,
            evaluation=eval_obj,
            business_risk="MEDIUM",
        )
        return elements

    def _kpi_tables(self, elements):
        """Gibt alle Tables mit genau 5 Spalten zurück (= unsere KPI-Zeile)."""
        return [e for e in elements if isinstance(e, Table) and len(e._colWidths) == 5]

    def test_kpi_row_is_present(self, styles):
        elements = self._run(styles, {"ip": "1.2.3.4", "open_ports": [{"port": 22, "product": "OpenSSH"}]})
        assert len(self._kpi_tables(elements)) == 1, "Es muss genau eine 5-spaltige KPI-Tabelle geben"

    def test_kpi_total_width_equals_163mm(self, styles):
        elements = self._run(styles, {"ip": "1.2.3.4"})
        kpi_tables = self._kpi_tables(elements)
        assert kpi_tables, "KPI-Zeile fehlt"
        total_w = sum(kpi_tables[0]._colWidths)
        assert abs(total_w - 163 * mm) < 0.1, (
            f"KPI-Gesamtbreite {total_w/mm:.2f} mm weicht von 163 mm ab"
        )

    def test_kpi_each_cell_width(self, styles):
        elements = self._run(styles, {"ip": "10.0.0.1"})
        kpi_tables = self._kpi_tables(elements)
        assert kpi_tables
        for w in kpi_tables[0]._colWidths:
            assert abs(w - _KPI_CELL_W * mm) < 0.1

    def test_kpi_ip_shown(self, styles):
        elements = self._run(styles, {"ip": "5.5.5.5"})
        kpi_tables = self._kpi_tables(elements)
        assert kpi_tables
        flat = []
        for row in kpi_tables[0]._cellvalues:
            for cell in row:
                if isinstance(cell, Table):
                    for r2 in cell._cellvalues:
                        for item in r2:
                            if isinstance(item, Paragraph):
                                flat.append(item.getPlainText())
        assert any("5.5.5.5" in t for t in flat)

    def test_kpi_crit_count_zero_neutral_color(self, styles):
        """Wenn keine kritischen CVEs vorhanden sind, darf Kritisch-Karte nicht rot sein."""
        from shodan_report.pdf.styles import Colors
        elements = self._run(styles, {"ip": "1.1.1.1"}, cves=[])
        kpi_tables = self._kpi_tables(elements)
        assert kpi_tables
        # Spalte index 3 = "Kritisch (≥9)"
        crit_cell = kpi_tables[0]._cellvalues[0][3]
        assert isinstance(crit_cell, Table)
        val_para = crit_cell._cellvalues[1][0]
        assert val_para.style.textColor == Colors.text

    def test_kpi_crit_count_nonzero_red_color(self, styles):
        """Wenn kritische CVEs vorhanden sind, muss Kritisch-Karte rot sein."""
        from shodan_report.pdf.styles import Colors
        cves = [{"id": "CVE-2023-0001", "cvss": 9.8, "exploit_status": None}]
        # Inject via mdata by putting cves into open_ports service cves
        technical_json = {
            "ip": "2.2.2.2",
            "open_ports": [{"port": 443, "product": "nginx", "cves": cves}],
        }
        eval_obj = {"ip": "2.2.2.2", "risk": "CRITICAL", "critical_points": [], "cves": cves}
        elements = []
        create_management_section(
            elements=elements,
            styles=styles,
            management_text="",
            technical_json=technical_json,
            evaluation=eval_obj,
            business_risk="CRITICAL",
        )
        kpi_tables = self._kpi_tables(elements)
        assert kpi_tables
        crit_cell = kpi_tables[0]._cellvalues[0][3]
        val_para = crit_cell._cellvalues[1][0]
        assert val_para.style.textColor == Colors.risk_critical_dot
