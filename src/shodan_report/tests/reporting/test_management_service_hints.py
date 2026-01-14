from shodan_report.reporting.management_text import generate_management_text
from shodan_report.evaluation.risk_prioritization import BusinessRisk
from shodan_report.evaluation.evaluation import Evaluation, RiskLevel


def test_service_hints_for_common_ports():
    evaluation = Evaluation(ip="1.1.1.1", risk=RiskLevel.HIGH, critical_points=[])

    technical_json = {
        "services": [
            {"port": 22, "product": "OpenSSH", "version": "8.2p1"},
            {"port": 443, "product": "nginx", "version": "1.20"},
            {"port": 80, "product": "Apache", "version": "2.4"},
        ]
    }

    text = generate_management_text(BusinessRisk.CRITICAL, evaluation, technical_json=technical_json)

    # SSH hint
    assert "Fail2Ban" in text or "SSH-Keys" in text

    # HTTPS hint
    assert "Zertifikat/Chain prüfen" in text

    # HTTP hint
    assert "HSTS" in text or "WAF" in text
