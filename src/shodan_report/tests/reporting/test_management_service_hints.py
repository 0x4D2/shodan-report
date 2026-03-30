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

    # Multiple services → multi-service scenario text
    assert "SSH" in text
    assert "Webserver" in text or "Web" in text
