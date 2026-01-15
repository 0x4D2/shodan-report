from shodan_report.pdf.sections.data.cve_enricher import enrich_cves_with_local


def test_enrich_cves_with_local_extracts_ports_and_cvss():
    technical_json = {
        "open_ports": [
            {"port": 22, "vulnerabilities": [{"id": "CVE-2025-0001", "cvss": 9.8}]},
            {"port": 80, "vulns": [{"id": "CVE-2025-0002", "cvss_score": 5.0}, {"id": "CVE-2025-0001", "cvss": 8.0}]},
        ],
    }
    cves = ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-9999"]
    enriched = enrich_cves_with_local(technical_json, cves)
    # Should return entries for each CVE
    ids = {e['id']: e for e in enriched}
    assert ids['CVE-2025-0001']['cvss'] == 9.8
    assert sorted(ids['CVE-2025-0001']['ports']) == [22, 80]
    assert ids['CVE-2025-0002']['cvss'] == 5.0
    assert ids['CVE-2025-0002']['ports'] == [80]
    # unknown CVE has no cvss and no ports
    assert ids['CVE-2025-9999']['cvss'] is None
    assert ids['CVE-2025-9999']['ports'] == []
