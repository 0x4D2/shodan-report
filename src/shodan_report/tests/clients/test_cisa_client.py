import types

from shodan_report.clients.cisa_client import CisaClient


class DummyResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


def test_fetch_kev_set_with_requests(monkeypatch):
    sample = {'vulnerabilities': [{'cveID': 'CVE-2021-0001'}, {'cveID': 'CVE-2021-0002'}]}

    dummy = DummyResponse(sample)

    import shodan_report.clients.cisa_client as mod
    monkeypatch.setattr(mod, 'requests', types.SimpleNamespace(get=lambda url, headers, timeout: dummy))
    c = CisaClient()
    s = c.fetch_kev_set()
    assert 'CVE-2021-0001' in s
    assert 'CVE-2021-0002' in s
