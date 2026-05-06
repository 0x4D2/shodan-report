"""Tests für clients/circl_client.py — CirclClient."""
import json
import pytest
from unittest.mock import MagicMock, patch
from shodan_report.clients.circl_client import CirclClient


def _make_response(data: dict, status: int = 200):
    """Erstellt einen minimalen requests.Response-Mock."""
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    if status >= 400:
        from requests.exceptions import HTTPError
        resp.raise_for_status.side_effect = HTTPError(response=resp)
    else:
        resp.raise_for_status.return_value = None
    return resp


def _valid_circl_payload(cvss=7.5, summary="Test vulnerability", cpe="cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"):
    return {
        "id": "CVE-2024-1234",
        "summary": summary,
        "cvss": cvss,
        "vulnerable_configuration": [cpe],
    }


# ── Happy Path ────────────────────────────────────────────────────────────────

def test_fetch_cve_json_returns_nvd_like_structure(monkeypatch):
    client = CirclClient()
    monkeypatch.setattr("shodan_report.clients.circl_client.requests",
                        MagicMock(get=lambda *a, **kw: _make_response(_valid_circl_payload())))
    result = client.fetch_cve_json("CVE-2024-1234")
    assert result is not None
    assert "CVE_Items" in result
    item = result["CVE_Items"][0]
    assert item["cve"]["CVE_data_meta"]["ID"] == "CVE-2024-1234"
    assert item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"] == 7.5


def test_fetch_cve_json_parses_vendor_product(monkeypatch):
    payload = _valid_circl_payload(cpe="cpe:2.3:a:apache:httpd:2.4.1:*:*:*:*:*:*:*")
    client = CirclClient()
    monkeypatch.setattr("shodan_report.clients.circl_client.requests",
                        MagicMock(get=lambda *a, **kw: _make_response(payload)))
    result = client.fetch_cve_json("CVE-2024-1234")
    vendor_data = result["CVE_Items"][0]["cve"]["affects"]["vendor"]["vendor_data"]
    assert vendor_data[0]["vendor_name"] == "apache"
    assert vendor_data[0]["product"]["product_data"][0]["product_name"] == "httpd"


def test_fetch_cve_json_summary_in_description(monkeypatch):
    payload = _valid_circl_payload(summary="Remote code execution")
    client = CirclClient()
    monkeypatch.setattr("shodan_report.clients.circl_client.requests",
                        MagicMock(get=lambda *a, **kw: _make_response(payload)))
    result = client.fetch_cve_json("CVE-2024-1234")
    desc = result["CVE_Items"][0]["cve"]["description"]["description_data"][0]["value"]
    assert desc == "Remote code execution"


# ── HTTP-Fehler ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("status", [404, 429, 500, 403])
def test_fetch_cve_json_http_error_returns_none(status, monkeypatch):
    client = CirclClient()
    monkeypatch.setattr("shodan_report.clients.circl_client.requests",
                        MagicMock(get=lambda *a, **kw: _make_response({}, status)))
    assert client.fetch_cve_json("CVE-2024-1234") is None


def test_fetch_cve_json_network_exception_returns_none(monkeypatch):
    import requests as req_mod
    mock_requests = MagicMock()
    mock_requests.get.side_effect = ConnectionError("timeout")
    monkeypatch.setattr("shodan_report.clients.circl_client.requests", mock_requests)
    assert CirclClient().fetch_cve_json("CVE-2024-1234") is None


# ── CVSS Edge Cases ───────────────────────────────────────────────────────────

def test_fetch_cve_json_missing_cvss(monkeypatch):
    payload = {"id": "CVE-X", "summary": "test"}
    client = CirclClient()
    monkeypatch.setattr("shodan_report.clients.circl_client.requests",
                        MagicMock(get=lambda *a, **kw: _make_response(payload)))
    result = client.fetch_cve_json("CVE-X")
    score = result["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
    assert score is None


def test_fetch_cve_json_cvss_empty_string(monkeypatch):
    """cvss='' → float('') würde ValueError — muss None ergeben, nicht crashen."""
    payload = {"id": "CVE-X", "summary": "test", "cvss": ""}
    client = CirclClient()
    monkeypatch.setattr("shodan_report.clients.circl_client.requests",
                        MagicMock(get=lambda *a, **kw: _make_response(payload)))
    result = client.fetch_cve_json("CVE-X")
    score = result["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
    assert score is None


# ── CPE / vulnerable_configuration Edge Cases ─────────────────────────────────

def test_fetch_cve_json_cpe_too_short(monkeypatch):
    """CPE mit weniger als 5 Teilen darf nicht crashen."""
    payload = {"id": "CVE-X", "cvss": 5.0, "vulnerable_configuration": ["cpe:2.3"]}
    client = CirclClient()
    monkeypatch.setattr("shodan_report.clients.circl_client.requests",
                        MagicMock(get=lambda *a, **kw: _make_response(payload)))
    result = client.fetch_cve_json("CVE-X")
    assert result is not None
    vendor_name = result["CVE_Items"][0]["cve"]["affects"]["vendor"]["vendor_data"][0]["vendor_name"]
    assert vendor_name == ""


def test_fetch_cve_json_vulnerable_configuration_dict(monkeypatch):
    """vulnerable_configuration als Dict statt Liste → wird ignoriert, kein Crash."""
    payload = {"id": "CVE-X", "cvss": 5.0, "vulnerable_configuration": {"cpe": "value"}}
    client = CirclClient()
    monkeypatch.setattr("shodan_report.clients.circl_client.requests",
                        MagicMock(get=lambda *a, **kw: _make_response(payload)))
    result = client.fetch_cve_json("CVE-X")
    assert result is not None


def test_fetch_cve_json_empty_response(monkeypatch):
    """Leere Antwort {} darf nicht crashen."""
    client = CirclClient()
    monkeypatch.setattr("shodan_report.clients.circl_client.requests",
                        MagicMock(get=lambda *a, **kw: _make_response({})))
    result = client.fetch_cve_json("CVE-X")
    assert result is not None
    assert "CVE_Items" in result
