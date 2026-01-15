from shodan_report.pdf.sections.data.recommendations_data import prepare_recommendations_data


def test_priority1_on_critical_cve():
    technical = {"open_ports": [], "vulnerabilities": []}
    evaluation = {"cves": [{"id": "CVE-2024-0001", "cvss": 9.0}]}
    out = prepare_recommendations_data(technical, evaluation, "MEDIUM")
    assert out["meta"]["critical_cves"] == 1
    assert any("Kritische CVE" in s for s in out["priority1"]) 


def test_tls_issues_marked_priority1():
    technical = {"tls_weaknesses": ["weak1"], "open_ports": []}
    evaluation = {}
    out = prepare_recommendations_data(technical, evaluation, "MEDIUM")
    assert out["meta"]["tls_issues"] >= 1
    assert any("TLS-Konfiguration" in s for s in out["priority1"]) 


def test_management_ports_and_dns_priority2():
    technical = {"open_ports": [{"port": 22, "product": "OpenSSH"}, {"port": 53, "product": "BIND"}]}
    evaluation = {}
    out = prepare_recommendations_data(technical, evaluation, "LOW")
    assert out["meta"]["dns_on_53"] is True
    assert "SSH" in out["meta"]["found_management_services"] or any("SSH" in s for s in out["priority2"]) 
