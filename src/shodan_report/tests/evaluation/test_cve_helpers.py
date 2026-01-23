import pytest

from shodan_report.evaluation.helpers.cve_helpers import (
    convert_to_cve_objects,
    count_cves_by_severity,
    generate_cve_message,
    CVE,
)


class DummyService:
    def __init__(self, product=None, version=None):
        self.product = product
        self.version = version


def test_convert_to_cve_objects_and_severity():
    raw = [
        {"id": "CVE-TEST-1", "cvss": "9.8", "summary": "crit"},
        {"id": "CVE-TEST-2", "cvss": "n/a"},
        {"id": "CVE-TEST-3", "cvss": 4.5},
        "CVE-TEST-4",
    ]

    cves = convert_to_cve_objects(raw)
    assert len(cves) == 4

    assert cves[0].id == "CVE-TEST-1"
    assert pytest.approx(cves[0].cvss) == 9.8
    assert cves[0].severity.name == "CRITICAL"

    assert cves[1].cvss == 0.0
    assert cves[2].severity.name == "MEDIUM"
    assert isinstance(cves[3], CVE)


def test_count_cves_by_severity():
    cves = [CVE("a", 9.8), CVE("b", 7.5), CVE("c", 4.5), CVE("d", 0.5), CVE("e", 0.0)]
    counts = count_cves_by_severity(cves)

    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert counts["medium"] == 1
    assert counts["low"] == 1
    assert counts["total"] == 5


def test_generate_cve_message_various():
    svc = DummyService(product="nginx", version="1.2")

    counts = {"critical": 2, "high": 0, "total": 2}
    assert generate_cve_message(counts, svc) == "2 kritische CVEs (nginx 1.2)"

    counts2 = {"critical": 0, "high": 1, "total": 1}
    msg = generate_cve_message(counts2, svc)
    assert "hochriskante" in msg

    counts3 = {"total": 0}
    assert generate_cve_message(counts3, svc) == ""
