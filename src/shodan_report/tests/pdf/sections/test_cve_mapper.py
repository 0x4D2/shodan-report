from shodan_report.pdf.sections.data.cve_mapper import normalize_cve_id, assign_cves_to_services


def test_normalize_cve_id_variants():
    assert normalize_cve_id(None) == ""
    assert normalize_cve_id("CVE-2023-12345") == "CVE-2023-12345"
    assert normalize_cve_id({"id": "CVE-2022-0001"}) == "CVE-2022-0001"
    class Obj:
        def __init__(self):
            self.cve = "CVE-2021-0002"

    assert normalize_cve_id(Obj()) == "CVE-2021-0002"


def test_assign_cves_to_services_basic():
    technical_json = {
        "open_ports": [
            {"port": 80, "vulnerabilities": ["CVE-2023-1111", {"id": "CVE-2023-2222"}]},
            {"port": 443, "vulns": ["CVE-2023-3333"]},
        ],
        "vulns": ["CVE-2023-1111", "CVE-2023-2222", "CVE-2023-3333", "CVE-2023-4444"],
    }

    result = assign_cves_to_services(technical_json, technical_json["vulns"])
    assert "per_service" in result and "unassigned" in result
    per = {p["port"]: p["cves"] for p in result["per_service"]}
    assert per[80] == ["CVE-2023-1111", "CVE-2023-2222"]
    assert per[443] == ["CVE-2023-3333"]
    assert result["unassigned"] == ["CVE-2023-4444"]
