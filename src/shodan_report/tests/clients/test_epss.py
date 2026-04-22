"""Tests für shodan_report.clients.epss"""
from unittest.mock import MagicMock, patch

import pytest

from shodan_report.clients.epss import get_epss_scores


def _make_response(status_code: int, data: list) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = {"data": data, "status": "OK"}
    return resp


_SAMPLE_DATA = [
    {"cve": "CVE-2021-44228", "epss": "0.9445", "percentile": "0.9997"},
    {"cve": "CVE-2014-0160",  "epss": "0.9734", "percentile": "0.9999"},
    {"cve": "CVE-2023-12345", "epss": "0.0012", "percentile": "0.1234"},
]


class TestGetEpssScoresStructure:
    def test_returns_dict(self):
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, _SAMPLE_DATA)
            result = get_epss_scores(["CVE-2021-44228"])
        assert isinstance(result, dict)

    def test_empty_list_returns_empty_dict(self):
        result = get_epss_scores([])
        assert result == {}

    def test_values_are_floats(self):
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, _SAMPLE_DATA)
            result = get_epss_scores(["CVE-2021-44228"])
        for v in result.values():
            assert isinstance(v, float)

    def test_scores_between_zero_and_one(self):
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, _SAMPLE_DATA)
            result = get_epss_scores(["CVE-2021-44228", "CVE-2014-0160", "CVE-2023-12345"])
        for v in result.values():
            assert 0.0 <= v <= 1.0


class TestGetEpssScoresLookup:
    def test_known_cve_returns_score(self):
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, _SAMPLE_DATA)
            result = get_epss_scores(["CVE-2021-44228"])
        assert "CVE-2021-44228" in result
        assert abs(result["CVE-2021-44228"] - 0.9445) < 0.001

    def test_unknown_cve_not_in_result(self):
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, _SAMPLE_DATA)
            result = get_epss_scores(["CVE-9999-0000"])
        assert "CVE-9999-0000" not in result

    def test_multiple_cves_all_returned(self):
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, _SAMPLE_DATA)
            result = get_epss_scores(["CVE-2021-44228", "CVE-2014-0160"])
        assert "CVE-2021-44228" in result
        assert "CVE-2014-0160" in result

    def test_keys_are_uppercase(self):
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, _SAMPLE_DATA)
            result = get_epss_scores(["CVE-2021-44228"])
        for key in result:
            assert key == key.upper()

    def test_low_epss_score_returned(self):
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, _SAMPLE_DATA)
            result = get_epss_scores(["CVE-2023-12345"])
        assert result.get("CVE-2023-12345", 0) < 0.01


class TestGetEpssScoresErrorHandling:
    def test_http_error_returns_empty(self):
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(500, [])
            result = get_epss_scores(["CVE-2021-44228"])
        assert result == {}

    def test_network_exception_returns_empty(self):
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.side_effect = Exception("Timeout")
            result = get_epss_scores(["CVE-2021-44228"])
        assert result == {}

    def test_malformed_response_skipped(self):
        bad_data = [
            {"cve": "CVE-2021-44228", "epss": "not_a_number"},
            {"cve": None, "epss": "0.5"},
        ]
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, bad_data)
            result = get_epss_scores(["CVE-2021-44228"])
        assert result == {}

    def test_partial_failure_returns_successful_entries(self):
        mixed_data = [
            {"cve": "CVE-2021-44228", "epss": "0.9445"},
            {"cve": "CVE-2014-0160",  "epss": "invalid"},
        ]
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, mixed_data)
            result = get_epss_scores(["CVE-2021-44228", "CVE-2014-0160"])
        assert "CVE-2021-44228" in result
        assert "CVE-2014-0160" not in result


class TestGetEpssScoresChunking:
    def test_large_list_makes_multiple_requests(self):
        # 150 CVEs → 2 Requests (chunk size = 100)
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(150)]
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, [])
            get_epss_scores(cve_ids)
        assert m.get.call_count == 2

    def test_exactly_100_cves_makes_one_request(self):
        cve_ids = [f"CVE-2024-{i:04d}" for i in range(100)]
        with patch("shodan_report.clients.epss._requests") as m:
            m.get.return_value = _make_response(200, [])
            get_epss_scores(cve_ids)
        assert m.get.call_count == 1
