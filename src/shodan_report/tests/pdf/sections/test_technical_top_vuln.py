from shodan_report.pdf.sections.data.technical_data import prepare_technical_detail


def test_top_vuln_and_risk_escalation_for_db_port():
    technical_json = {
        "open_ports": [
            {"port": 3306, "service": {"product": "MySQL"}, "vulnerabilities": [{"id": "CVE-2025-0001", "cvss": 6.5}]},
            {"port": 80, "service": {"product": "HTTP"}, "vulnerabilities": [{"id": "CVE-2025-0002", "cvss": 7.5}]},
        ],
    }
    result = prepare_technical_detail(technical_json, {})
    services = {s["port"]: s for s in result["services"]}
    # DB port should be escalated to 'hoch' because it's a DB port
    assert services[3306]["risk"] == "hoch"
    # top_vuln for port 80 should be CVE-2025-0002 with cvss 7.5
    assert services[80]["top_vuln"]["id"] == "CVE-2025-0002"
    assert services[80]["top_vuln"]["cvss"] == 7.5
