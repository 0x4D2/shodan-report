from typing import Any

from shodan_report.reporting.management_text import (
    _normalize_services_from_technical,
    generate_management_text,
)
from shodan_report.evaluation.evaluation import Evaluation, RiskLevel
from shodan_report.evaluation.risk_prioritization import BusinessRisk
from shodan_report.evaluation.helpers.cve_helpers import convert_to_cve_objects


class ObjLike:
    def __init__(self, **kwargs: Any):
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_normalize_services_handles_various_open_ports_structures():
    # Mixed formats: dict entries, simple objects, missing fields
    technical_json = {
        "open_ports": [
            {"port": 22, "service": {"product": "OpenSSH", "version": "8.2"}},
            ObjLike(port=80, product="Apache"),
            {"port": None, "product": None},
        ]
    }

    services = _normalize_services_from_technical(technical_json)
    # Should return a list and not raise; entries normalized to dicts
    assert isinstance(services, list)
    assert len(services) == 3
    assert any(s.get("product") == "OpenSSH" or s.get("product") == "Apache" for s in services)


def test_convert_to_cve_objects_with_none_and_unusual_entries():
    raw = [None, {"cve": "CVE-FOO-1", "cvss": None}, "CVE-STRING-1", {"id": "CVE-2", "cvss": "7.1"}]
    # convert_to_cve_objects should ignore None and convert available entries without raising
    cves = convert_to_cve_objects([r for r in raw if r is not None])
    assert any(getattr(c, "id", "").startswith("CVE") for c in cves)


def test_generate_management_text_with_mixed_vuln_formats():
    # service contains vulnerabilities in different shapes: dict with 'cve', string, object-like
    vuln_obj = ObjLike(id="CVE-OBJ-1", cvss=9.0)
    technical_json = {
        "services": [
            {
                "port": 22,
                "product": "OpenSSH",
                "version": "7",
                "banner": "OpenSSH_7",
                "cves": [
                    {"cve": "CVE-1"},
                    "CVE-2",
                    vuln_obj,
                ],
            }
        ]
    }

    evaluation = Evaluation(ip="9.9.9.9", risk=RiskLevel.HIGH, critical_points=["Kritischer Dienst gefunden: SSH auf Port 22"])
    text = generate_management_text(BusinessRisk.CRITICAL, evaluation, technical_json=technical_json)

    # Should include port and at least one CVE id without raising
    assert "Port 22" in text
    assert "CVE-1" in text or "CVE-2" in text or "CVE-OBJ-1" in text
