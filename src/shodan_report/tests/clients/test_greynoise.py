"""Tests für shodan_report.clients.greynoise"""
import pytest
from unittest.mock import patch, MagicMock

from shodan_report.clients.greynoise import get_greynoise_status


_EMPTY = {
    "available": False,
    "noise": False,
    "riot": False,
    "classification": "unknown",
    "name": "",
    "last_seen": "",
}


def _make_response(status_code: int, json_data: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    return resp


class TestGetGreynoiseStatusStructure:
    def test_returns_dict_with_all_keys(self):
        with patch("shodan_report.clients.greynoise._requests") as m:
            m.get.return_value = _make_response(200, {
                "noise": False, "riot": True, "classification": "benign",
                "name": "Google LLC", "last_seen": "2026-04-10",
            })
            result = get_greynoise_status("8.8.8.8")
        for key in ("available", "noise", "riot", "classification", "name", "last_seen", "link"):
            assert key in result

    def test_link_contains_ip(self):
        with patch("shodan_report.clients.greynoise._requests") as m:
            m.get.return_value = _make_response(200, {"noise": False, "riot": False, "classification": "unknown"})
            result = get_greynoise_status("1.2.3.4")
        assert "1.2.3.4" in result["link"]

    def test_empty_ip_returns_unavailable(self):
        result = get_greynoise_status("")
        assert result["available"] is False

    def test_none_ip_returns_unavailable(self):
        result = get_greynoise_status(None)
        assert result["available"] is False


class TestGetGreynoiseStatusApiResponses:
    def test_200_riot_true(self):
        with patch("shodan_report.clients.greynoise._requests") as m:
            m.get.return_value = _make_response(200, {
                "noise": False, "riot": True, "classification": "benign",
                "name": "Google LLC", "last_seen": "2026-04-10",
            })
            r = get_greynoise_status("8.8.8.8")
        assert r["available"] is True
        assert r["riot"] is True
        assert r["noise"] is False
        assert r["classification"] == "benign"
        assert r["name"] == "Google LLC"

    def test_200_malicious(self):
        with patch("shodan_report.clients.greynoise._requests") as m:
            m.get.return_value = _make_response(200, {
                "noise": True, "riot": False, "classification": "malicious",
                "name": "", "last_seen": "2026-04-15",
            })
            r = get_greynoise_status("185.1.2.3")
        assert r["available"] is True
        assert r["noise"] is True
        assert r["classification"] == "malicious"

    def test_404_returns_available_clean(self):
        with patch("shodan_report.clients.greynoise._requests") as m:
            m.get.return_value = _make_response(404, {})
            r = get_greynoise_status("10.0.0.1")
        assert r["available"] is True
        assert r["noise"] is False

    def test_500_returns_unavailable(self):
        with patch("shodan_report.clients.greynoise._requests") as m:
            m.get.return_value = _make_response(500, {})
            r = get_greynoise_status("1.2.3.4")
        assert r["available"] is False

    def test_timeout_returns_unavailable(self):
        import requests as req_lib
        with patch("shodan_report.clients.greynoise._requests") as m:
            m.get.side_effect = Exception("timeout")
            r = get_greynoise_status("1.2.3.4")
        assert r["available"] is False

    def test_classification_normalized_to_lowercase(self):
        with patch("shodan_report.clients.greynoise._requests") as m:
            m.get.return_value = _make_response(200, {
                "noise": True, "riot": False, "classification": "Malicious",
            })
            r = get_greynoise_status("1.2.3.4")
        assert r["classification"] == "malicious"

    def test_api_key_sent_in_header(self):
        with patch("shodan_report.clients.greynoise._requests") as m:
            m.get.return_value = _make_response(200, {"noise": False, "riot": False})
            get_greynoise_status("1.2.3.4", api_key="testkey123")
        call_kwargs = m.get.call_args
        headers = call_kwargs[1]["headers"] if "headers" in call_kwargs[1] else call_kwargs[0][1]
        assert headers.get("key") == "testkey123"


class TestGetGreynoiseStatusEnvKey:
    def test_env_key_used_when_no_explicit_key(self):
        with patch("shodan_report.clients.greynoise._requests") as m, \
             patch("shodan_report.clients.greynoise.os") as mock_os:
            mock_os.getenv.return_value = "envkey456"
            m.get.return_value = _make_response(200, {"noise": False, "riot": False})
            get_greynoise_status("1.2.3.4")
        call_kwargs = m.get.call_args
        headers = call_kwargs[1].get("headers") or {}
        assert headers.get("key") == "envkey456"


class TestManagementKpiGreynoise:
    """Integration: management.py GreyNoise KPI rendering."""

    def _make_tech_json(self):
        return {"ip_str": "1.2.3.4", "services": [{"port": 80, "product": "nginx"}]}

    def _make_eval(self):
        return {"risk_level": "low", "exposure_score": 2, "critical_points": []}

    def _paragraphs(self, el) -> list:
        from reportlab.platypus import Paragraph, Table
        results = []
        def _walk(obj):
            if isinstance(obj, Paragraph):
                results.append(obj.text)
            elif isinstance(obj, Table):
                for row in obj._cellvalues:
                    for cell in row:
                        if isinstance(cell, list):
                            for item in cell:
                                _walk(item)
                        else:
                            _walk(cell)
        _walk(el)
        return results

    def _render(self, greynoise=None):
        from shodan_report.pdf.sections.management import create_management_section
        from shodan_report.pdf.styles import create_theme, create_styles
        theme = create_theme("#1a365d", "#2d3748")
        styles = create_styles(theme)
        elements = []
        from shodan_report.pdf.context import ReportContext
        ctx = ReportContext(
            customer_name="TestCo",
            month="2026-04",
            ip="1.2.3.4",
            management_text="",
            trend_text="",
            technical_json=self._make_tech_json(),
            evaluation=self._make_eval(),
            business_risk="low",
            greynoise=greynoise,
        )
        create_management_section(elements=elements, styles=styles, context=ctx)
        return elements

    def test_greynoise_kpi_label_present(self):
        elements = self._render({"available": True, "noise": False, "riot": False, "classification": "unknown"})
        texts = []
        for el in elements:
            texts.extend(self._paragraphs(el))
        full = " ".join(texts)
        assert "GREYNOISE" in full

    def test_riot_shows_green_value(self):
        elements = self._render({"available": True, "noise": False, "riot": True, "classification": "benign", "name": "Google"})
        texts = []
        for el in elements:
            texts.extend(self._paragraphs(el))
        full = " ".join(texts)
        assert "RIOT" in full

    def test_malicious_shows_value(self):
        elements = self._render({"available": True, "noise": True, "riot": False, "classification": "malicious"})
        texts = []
        for el in elements:
            texts.extend(self._paragraphs(el))
        full = " ".join(texts)
        assert "MALICIOUS" in full

    def test_unavailable_shows_dash(self):
        elements = self._render({"available": False, "noise": False, "riot": False, "classification": "unknown"})
        texts = []
        for el in elements:
            texts.extend(self._paragraphs(el))
        full = " ".join(texts)
        assert "GREYNOISE" in full

    def test_greynoise_sentence_in_gesamteinschaetzung_malicious(self):
        elements = self._render({"available": True, "noise": True, "riot": False, "classification": "malicious", "name": ""})
        texts = []
        for el in elements:
            texts.extend(self._paragraphs(el))
        full = " ".join(texts)
        assert "Bedrohungsakteur" in full

    def test_greynoise_sentence_riot_includes_name(self):
        elements = self._render({"available": True, "noise": False, "riot": True, "classification": "benign", "name": "Cloudflare"})
        texts = []
        for el in elements:
            texts.extend(self._paragraphs(el))
        full = " ".join(texts)
        assert "Cloudflare" in full

    def test_greynoise_clean_sentence(self):
        elements = self._render({"available": True, "noise": False, "riot": False, "classification": "unknown", "name": ""})
        texts = []
        for el in elements:
            texts.extend(self._paragraphs(el))
        full = " ".join(texts)
        assert "unauffällig" in full

    def test_no_greynoise_no_sentence(self):
        elements = self._render(None)
        texts = []
        for el in elements:
            texts.extend(self._paragraphs(el))
        full = " ".join(texts)
        # No GreyNoise-specific terminology
        assert "Bedrohungsakteur" not in full
        assert "GreyNoise" not in full
