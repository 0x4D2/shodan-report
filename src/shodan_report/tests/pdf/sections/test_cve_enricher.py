from shodan_report.pdf.sections.data.cve_enricher import enrich_cves_no_key


def test_enrich_cves_no_key_shape_and_urls():
    cves = ["CVE-2023-0001", "CVE-2023-0002", ""]
    enriched = enrich_cves_no_key(cves)
    assert isinstance(enriched, list)
    ids = [e["id"] for e in enriched]
    assert "CVE-2023-0001" in ids and "CVE-2023-0002" in ids
    for e in enriched:
        assert e["nvd_url"].startswith("https://nvd.nist.gov/vuln/detail/")
        assert e["summary"] is None
