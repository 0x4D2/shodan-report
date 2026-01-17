import json

from src.shodan_report.clients.nvd_client import NvdClient


def test_default_headers_include_api_key_when_provided():
    c = NvdClient(api_key='my-secret')
    headers = c._default_headers()
    assert headers.get('apiKey') == 'my-secret'


def test_fetch_cve_json_uses_fetch_cve(monkeypatch):
    c = NvdClient()

    sample = {'result': {'CVE_Items': [{'cve': {'CVE_data_meta': {'ID': 'CVE-2020-0001'}}}]}}

    def fake_fetch(cve_id):
        return 200, {}, json.dumps(sample)

    monkeypatch.setattr(c, 'fetch_cve', fake_fetch)
    j = c.fetch_cve_json('CVE-2020-0001')
    assert isinstance(j, dict)
    assert j.get('result')
