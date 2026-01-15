import types

from shodan_report.pdf.sections.data.management_data import prepare_management_data


class EvalObj:
    def __init__(self):
        self.exposure_score = 3
        self.risk = types.SimpleNamespace(value="High")
        self.critical_points = ["Point A", "Point B"]
        self.cves = ["CVE-2020-AAAA"]


def test_prepare_with_dict_evaluation():
    technical = {
        "open_ports": [
            {"port": 22, "product": "OpenSSH", "vulns": ["CVE-2019-1111"]},
            {"port": 80, "product": "nginx", "vulnerabilities": ["CVE-2018-2222"]},
        ],
        "vulns": ["CVE-2017-3333"],
    }
    evaluation = {
        "exposure_score": 4,
        "risk": "risklevel.HIGH",
        "critical_points": ["A"],
        "cves": ["CVE-2016-4444"],
    }

    out = prepare_management_data(technical, evaluation)

    assert out["exposure_score"] == 4
    assert out["risk_level"] == "high"
    assert out["total_ports"] == 2
    assert out["cve_count"] >= 3
    assert "CVE-2019-1111" in out["unique_cves"]


def test_prepare_with_object_evaluation_and_object_technical():
    # technical as object with attributes
    tech = types.SimpleNamespace()
    tech.open_ports = [types.SimpleNamespace(port=443, product="Apache", vulnerabilities=["CVE-2021-5555"])]
    tech.vulns = ["CVE-2021-6666"]

    eval_obj = EvalObj()

    out = prepare_management_data(tech, eval_obj)

    assert out["exposure_score"] == 3
    assert out["risk_level"] == "high"
    assert out["total_ports"] == 1
    assert "CVE-2021-5555" in out["unique_cves"]
    assert "CVE-2020-AAAA" in out["unique_cves"]


def test_prepare_handles_missing_fields_gracefully():
    out = prepare_management_data({}, {})
    assert out["exposure_score"] == 1
    assert out["risk_level"] == "low"
    assert out["total_ports"] == 0
    assert out["cve_count"] == 0
