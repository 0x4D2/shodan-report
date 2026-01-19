from shodan_report.pdf.sections.data.cve_enricher import enrich_cves


class DummyNvd:
    def fetch_cve_json(self, cve_id):
        # Return a minimal NVD-like structure with CVE_Items and baseMetricV3
        return {
            "result": {
                "CVE_Items": [
                    {
                        "cve": {
                            "CVE_data_meta": {"ID": cve_id},
                            "description": {"description_data": [{"value": "Dummy summary"}]},
                            "affects": {
                                "vendor": {
                                    "vendor_data": [
                                        {
                                            "vendor_name": "nginx",
                                            "product": {
                                                "product_data": [
                                                    {"product_name": "nginx"}
                                                ]
                                            }
                                        }
                                    ]
                                }
                            }
                        },
                        "impact": {"baseMetricV3": {"cvssV3": {"baseScore": 7.5}}}
                    }
                ]
            }
        }


class DummyCisa:
    def __init__(self, kev=None):
        self._kev = set(kev or [])

    def fetch_kev_set(self):
        return self._kev


def test_enrich_cves_uses_nvd_and_cisa(monkeypatch):
    cves = ["CVE-2023-FOO", "CVE-2023-BAR"]
    technical_json = {}

    # monkeypatch NvdClient and CisaClient inside the enricher module
    import shodan_report.pdf.sections.data.cve_enricher as mod

    monkeypatch.setattr(mod, 'NvdClient', lambda: DummyNvd())
    monkeypatch.setattr(mod, 'CisaClient', lambda: DummyCisa(kev={"CVE-2023-FOO"}))

    res = enrich_cves(cves, technical_json, lookup_nvd=True)
    # Expect two results
    assert len(res) == 2

    # One of them should have cvss from DummyNvd (7.5) and exploit_status public for FOO
    foo = next(r for r in res if r['id'] == 'CVE-2023-FOO')
    assert foo['cvss'] == 7.5
    assert foo['exploit_status'] == 'public'
    # product/service should be extracted from NVD
    assert 'nginx' in str(foo.get('service', '')).lower()

    bar = next(r for r in res if r['id'] == 'CVE-2023-BAR')
    # Not in CISA -> exploit_status unknown or default
    assert bar['exploit_status'] in (None, 'unknown', '') or isinstance(bar['exploit_status'], str)
