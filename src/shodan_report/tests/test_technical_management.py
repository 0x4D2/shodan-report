import pytest

from shodan_report.pdf.sections.data.technical_data import prepare_technical_detail
from shodan_report.pdf.sections.data.management_data import prepare_management_data


def test_server_and_version_extraction():
    technical = {
        "services": [
            {
                "port": 8443,
                "product": "HTTP",
                "version": "",
                "banner": "HTTP/1.1\r\nServer: Apereo CAS\r\nDate: Tue\r\n",
            }
        ]
    }

    res = prepare_technical_detail(technical, {})
    assert res["meta"]["total_services"] == 1
    svc = res["services"][0]
    assert svc["server"] == "Apereo CAS"
    # Accept either '1.1' or 'HTTP/1.1' depending on sanitization path
    assert "1.1" in svc["version"]


def test_mysql_version_preserved():
    technical = {"services": [{"port": 3306, "product": "MySQL", "version": "8.0.33", "banner": ""}]}
    res = prepare_technical_detail(technical, {})
    svc = res["services"][0]
    assert svc["version"] == "8.0.33"
    assert svc["server"] == ""


def test_management_cve_and_critical_dedup():
    technical = {
        "services": [
            {"port": 3306, "product": "MySQL", "vulnerabilities": ["CVE-2024-1234", {"id": "CVE-2024-1234"}]},
            {"port": 80, "product": "HTTP", "vulnerabilities": ["CVE-2025-9999"]},
        ],
        "vulns": ["CVE-2026-0001"],
    }

    evaluation = {"cves": ["CVE-2024-1234"], "critical_points": ["MySQL 8.0.33 vulnerable", "MySQL 8.0.33 vulnerable"]}

    mg = prepare_management_data(technical, evaluation)

    # unique CVEs should include per-service and top-level entries
    assert mg["cve_count"] == 3
    assert mg["critical_points_count"] == 1
    assert "CVE-2024-1234" in mg["unique_cves"]


import pytest


@pytest.mark.parametrize("svc", [
    {"port": 8443, "product": "HTTP", "version": "", "banner": "HTTP/1.1\r\nServer: Apereo CAS\r\nDate: Tue\r\n"},
    {"port": 80, "product": "", "version": "", "banner": "Server: nginx/1.18.0\r\nContent-Type: text/html\r\n"},
    {"port": 80, "product": "", "version": "", "banner": "1.1 200 OK\r\n"},
    {"port": 8080, "product": "HTTP", "version": "", "banner": ("Content-Type: text/html\r\n" * 8)},
    {"port": 22, "product": "OpenSSH", "version": "7.6p1 Ubuntu 4ubuntu0.7", "banner": ""},
])
def test_banner_extraction_clean(svc):
    res = prepare_technical_detail({"services": [svc]}, {})
    s = res["services"][0]
    ver = s["version"]
    server = s["server"]

    # version and server must not contain raw newlines and should be reasonably short
    assert "\n" not in ver and "\r" not in ver
    assert "\n" not in server and "\r" not in server
    assert len(ver) <= 80

    # If nginx/1.18.0 appears in banner, the numeric version should be extracted
    if "1.18.0" in svc.get("banner", ""):
        assert "1.18.0" in ver or "1.18.0" in server

    # If HTTP token or leading numeric appears, ensure '1.1' is present somewhere
    if svc.get("banner", "").startswith("1.1") or "HTTP/1.1" in svc.get("banner", ""):
        assert "1.1" in ver or "1.1" in server

    # If explicit product version provided, it should be preserved
    if svc.get("product") == "OpenSSH":
        assert "7.6" in ver
