from shodan_report.pdf.sections.data.recommendations_data import prepare_recommendations_data


def test_priority1_on_critical_cve():
    technical = {"open_ports": [], "vulnerabilities": []}
    evaluation = {"cves": [{"id": "CVE-2024-0001", "cvss": 9.0}]}
    out = prepare_recommendations_data(technical, evaluation, "MEDIUM")
    assert out["meta"]["critical_cves"] == 1
    assert any("CVEs patchen" in s or "kritisch" in s for s in out["priority1"])
    assert any(action["priority"] == "critical" for action in out["priority1_actions"])
    assert any("cve" in action["id"] for action in out["priority1_actions"])


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
    assert any(action["priority"] == "recommended" for action in out["priority2_actions"])


def test_expiring_certificate_creates_deadline_action():
    technical = {
        "open_ports": [
            {"port": 443, "product": "nginx", "tls": {"cert_expiry": "2026-06-01", "cert_expires_in_days": 10}},
        ]
    }
    out = prepare_recommendations_data(technical, {}, "LOW")
    cert_action = next((a for a in out["priority1_actions"] if a["id"] == "critical-renew-cert-443"), None)
    assert cert_action is not None
    assert cert_action["deadline"] == "2026-06-01"
    assert cert_action["duration_minutes"] == 30
    assert cert_action["cost_max"] == 50
