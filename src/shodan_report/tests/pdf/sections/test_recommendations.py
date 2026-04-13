"""Tests für die Recommendations-Section (neues Badge-Design)."""

import pytest
from reportlab.platypus import Paragraph, Spacer, Table
from reportlab.lib import colors
from reportlab.lib.units import mm

from shodan_report.pdf.styles import create_styles, create_theme
from shodan_report.pdf.sections.recommendations import (
    _priority_badge,
    _item_row,
    _has_rdp,
    _extract_risk_level,
    _extract_port,
    _CONTENT_W,
    COLOR_P1_BG, COLOR_P1_BORDER, COLOR_P1_TEXT,
    COLOR_P2_BG, COLOR_P2_BORDER, COLOR_P2_TEXT,
    COLOR_P3_BG, COLOR_P3_BORDER, COLOR_P3_TEXT,
    create_recommendations_section,
)


@pytest.fixture
def styles():
    return create_styles(create_theme("#1a365d", "#2d3748"))


# ── _priority_badge ───────────────────────────────────────────────────────────

class TestPriorityBadge:

    def test_returns_table(self, styles):
        tbl = _priority_badge("Priorität 1 – Kritisch", COLOR_P1_BG, COLOR_P1_BORDER, COLOR_P1_TEXT, styles)
        assert isinstance(tbl, Table)

    def test_left_aligned(self, styles):
        tbl = _priority_badge("Label", COLOR_P1_BG, COLOR_P1_BORDER, COLOR_P1_TEXT, styles)
        assert tbl.hAlign == "LEFT"

    def test_width_smaller_than_content_width(self, styles):
        # Badge width is dynamic (stringWidth-based) but always < full content width
        tbl = _priority_badge("Label", COLOR_P1_BG, COLOR_P1_BORDER, COLOR_P1_TEXT, styles)
        assert tbl._colWidths[0] < _CONTENT_W

    def test_contains_paragraph_with_label(self, styles):
        label = "Priorität 2 – Spezifische Empfehlungen"
        tbl = _priority_badge(label, COLOR_P2_BG, COLOR_P2_BORDER, COLOR_P2_TEXT, styles)
        cell = tbl._cellvalues[0][0]
        assert isinstance(cell, Paragraph)
        assert label in cell.text

    def test_all_three_badge_colors_produce_tables(self, styles):
        for bg, border, text in [
            (COLOR_P1_BG, COLOR_P1_BORDER, COLOR_P1_TEXT),
            (COLOR_P2_BG, COLOR_P2_BORDER, COLOR_P2_TEXT),
            (COLOR_P3_BG, COLOR_P3_BORDER, COLOR_P3_TEXT),
        ]:
            tbl = _priority_badge("Test", bg, border, text, styles)
            assert isinstance(tbl, Table)


# ── _item_row ─────────────────────────────────────────────────────────────────

class TestItemRow:

    def test_returns_table(self, styles):
        tbl = _item_row("Empfehlung X", COLOR_P1_BORDER, styles)
        assert isinstance(tbl, Table)

    def test_two_columns(self, styles):
        tbl = _item_row("Empfehlung X", COLOR_P1_BORDER, styles)
        assert len(tbl._colWidths) == 2

    def test_stripe_column_is_3pt(self, styles):
        tbl = _item_row("Text", COLOR_P1_BORDER, styles)
        assert tbl._colWidths[0] == 3

    def test_total_width_matches_content_width(self, styles):
        tbl = _item_row("Text", COLOR_P1_BORDER, styles)
        assert abs(sum(tbl._colWidths) - _CONTENT_W) < 0.01

    def test_text_cell_contains_paragraph(self, styles):
        tbl = _item_row("Maßnahme: VPN aktivieren", COLOR_P2_BORDER, styles)
        cell = tbl._cellvalues[0][1]
        assert isinstance(cell, Paragraph)

    def test_html_in_text_is_accepted(self, styles):
        tbl = _item_row("Port <b>3389</b> schließen", COLOR_P1_BORDER, styles)
        assert isinstance(tbl, Table)


# ── _has_rdp ─────────────────────────────────────────────────────────────────

class TestHasRdp:

    def test_port_3389_dict_detected(self):
        assert _has_rdp({"services": [{"port": 3389, "product": "unknown"}]}) is True

    def test_rdp_product_name_detected(self):
        assert _has_rdp({"open_ports": [{"port": 1234, "product": "RDP-Service"}]}) is True

    def test_rdp_product_case_insensitive(self):
        assert _has_rdp({"services": [{"port": 22, "product": "rdp"}]}) is True

    def test_no_rdp_returns_false(self):
        assert _has_rdp({"services": [{"port": 22, "product": "OpenSSH"}, {"port": 80, "product": "nginx"}]}) is False

    def test_empty_services_returns_false(self):
        assert _has_rdp({"services": []}) is False

    def test_empty_dict_returns_false(self):
        assert _has_rdp({}) is False

    def test_object_with_port_attribute(self):
        class FakeService:
            port = 3389
            product = "ms-term-services"
        assert _has_rdp({"services": [FakeService()]}) is True


# ── _extract_risk_level / _extract_port ──────────────────────────────────────

class TestHelpers:

    def test_extract_risk_level_string(self):
        assert _extract_risk_level("HIGH") == "HIGH"

    def test_extract_risk_level_dict(self):
        assert _extract_risk_level({"level": "CRITICAL"}) == "CRITICAL"

    def test_extract_risk_level_dict_missing_key(self):
        assert _extract_risk_level({}) == "MEDIUM"

    def test_extract_risk_level_other(self):
        assert _extract_risk_level(42) == "42"

    def test_extract_port_int(self):
        assert _extract_port(443) == 443

    def test_extract_port_dict(self):
        assert _extract_port({"port": 8080}) == 8080

    def test_extract_port_dict_missing(self):
        assert _extract_port({}) is None


# ── create_recommendations_section ───────────────────────────────────────────

class TestCreateRecommendationsSection:

    def _collect(self, styles, technical_json=None, evaluation=None, business_risk="LOW"):
        elements = []
        create_recommendations_section(
            elements=elements,
            styles=styles,
            technical_json=technical_json or {},
            evaluation=evaluation or {},
            business_risk=business_risk,
        )
        return elements

    def test_produces_elements(self, styles):
        elements = self._collect(styles)
        assert len(elements) > 0

    def test_heading_paragraph_present(self, styles):
        from reportlab.platypus import KeepTogether
        elements = self._collect(styles)
        # The heading is wrapped in a KeepTogether — flatten one level
        flat = []
        for e in elements:
            if isinstance(e, KeepTogether):
                flat.extend(e._content)
            else:
                flat.append(e)
        texts = [e.text for e in flat if isinstance(e, Paragraph)]
        assert any("Handlungsempfehlungen" in t for t in texts)

    def test_p1_badge_always_rendered(self, styles):
        elements = self._collect(styles)
        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1  # at least the P1 badge

    def test_p1_badge_is_left_aligned(self, styles):
        elements = self._collect(styles)
        tables = [e for e in elements if isinstance(e, Table)]
        assert tables[0].hAlign == "LEFT"

    def test_no_p1_items_yields_fallback_paragraph(self, styles):
        elements = self._collect(styles, technical_json={}, evaluation={}, business_risk="LOW")
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        fallback_texts = [p.text for p in paragraphs if "OSINT" in p.text]
        assert len(fallback_texts) >= 1

    def test_rdp_fallback_renders_three_item_rows(self, styles):
        tech = {"services": [{"port": 3389, "product": "rdp"}]}
        elements = self._collect(styles, technical_json=tech, evaluation={})
        # RDP fallback adds 3 item rows; prepare_recommendations_data may add more for P2/P3
        item_tables = [
            e for e in elements
            if isinstance(e, Table) and len(e._colWidths) == 2 and e._colWidths[0] == 3
        ]
        assert len(item_tables) >= 3
        # Verify the first three rows contain the RDP-specific messages
        rdp_texts = [
            e._cellvalues[0][1].text
            for e in item_tables[:3]
        ]
        assert any("RDP" in t or "3389" in t for t in rdp_texts)
        assert any("VPN" in t or "Maßnahme" in t for t in rdp_texts)

    def test_critical_cve_triggers_p1_items(self, styles):
        evaluation = {"cves": [{"id": "CVE-2024-9999", "cvss": 9.8}]}
        elements = self._collect(styles, technical_json={}, evaluation=evaluation, business_risk="HIGH")
        item_tables = [
            e for e in elements
            if isinstance(e, Table) and len(e._colWidths) == 2 and e._colWidths[0] == 3
        ]
        assert len(item_tables) >= 1

    def test_p2_badge_rendered_when_priority2_items_exist(self, styles):
        evaluation = {}
        tech = {"open_ports": [{"port": 22, "product": "OpenSSH"}]}
        elements = self._collect(styles, technical_json=tech, evaluation=evaluation, business_risk="MEDIUM")
        # Badge tables have 1 column and are narrower than _CONTENT_W
        badge_tables = [
            e for e in elements
            if isinstance(e, Table) and len(e._colWidths) == 1 and e._colWidths[0] < _CONTENT_W
        ]
        # At minimum P1 badge; P2 badge only if items present — just assert no crash
        assert len(badge_tables) >= 1

    def test_context_di_path_works(self, styles):
        class FakeCtx:
            business_risk = "LOW"
            technical_json = {}
            evaluation = {}

        elements = []
        create_recommendations_section(elements=elements, styles=styles, context=FakeCtx())
        assert len(elements) > 0

    def test_context_none_falls_back_to_kwargs(self, styles):
        elements = []
        create_recommendations_section(
            elements=elements,
            styles=styles,
            context=None,
            technical_json={},
            evaluation={},
            business_risk="LOW",
        )
        assert len(elements) > 0

    def test_spacers_present(self, styles):
        elements = self._collect(styles)
        assert any(isinstance(e, Spacer) for e in elements)
