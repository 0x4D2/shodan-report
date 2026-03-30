import pytest

from shodan_report.reporting.management_text import generate_management_text
from shodan_report.evaluation.risk_prioritization import BusinessRisk
from shodan_report.evaluation.evaluation import Evaluation, RiskLevel


@pytest.mark.parametrize(
    "business_risk, eval_risk, critical_points, expected_phrases",
    [
        (
            BusinessRisk.MONITOR,
            RiskLevel.LOW,
            [],
            ["stabil bewertet", "Kein unmittelbarer Handlungsbedarf"],
        ),
        (
            BusinessRisk.ATTENTION,
            RiskLevel.MEDIUM,
            ["Viele offene Dienste: 5", "Veraltete/anfällige Version: nginx 1.0"],
            ["erhöhte Risiken", "IT-Betrieb"],
        ),
        (
            BusinessRisk.CRITICAL,
            RiskLevel.HIGH,
            ["Kritischer Dienst gefunden: ssh auf Port 22"],
            ["Risikoindikatoren", "Maßnahmenplan"],
        ),
    ],
)
def test_generate_management_text_variants(
    business_risk, eval_risk, critical_points, expected_phrases
):
    evaluation = Evaluation(
        ip="1.2.3.4", risk=eval_risk, critical_points=critical_points
    )
    text = generate_management_text(business_risk, evaluation)

    for phrase in expected_phrases:
        assert phrase in text


def test_business_risk_parameter_takes_precedence():
    # CRITICAL ohne technical_json → generic critical text
    evaluation = Evaluation(ip="2.3.4.5", risk=RiskLevel.LOW, critical_points=[])
    text = generate_management_text(BusinessRisk.CRITICAL, evaluation)
    assert "Gesamteinschätzung" in text
    assert "Risikoindikatoren" in text


def test_many_critical_points_are_listed():
    critical_points = [f"Problem {i}" for i in range(1, 21)]
    evaluation = Evaluation(
        ip="3.3.3.3", risk=RiskLevel.HIGH, critical_points=critical_points
    )
    text = generate_management_text(BusinessRisk.CRITICAL, evaluation)
    assert "Gesamteinschätzung" in text


def test_handles_empty_critical_points():
    evaluation = Evaluation(ip="10.10.10.10", risk=RiskLevel.HIGH, critical_points=[])
    text = generate_management_text(BusinessRisk.CRITICAL, evaluation)
    assert "Gesamteinschätzung" in text


def test_critical_points_are_expanded_with_technical_json():
    # Simuliere einen Snapshot mit einem SSH-Dienst
    critical_points = ["Kritischer Dienst gefunden: SSH auf Port 22"]
    evaluation = Evaluation(ip="5.6.7.8", risk=RiskLevel.HIGH, critical_points=critical_points)

    technical_json = {
        "services": [
            {
                "port": 22,
                "product": "OpenSSH",
                "version": "8.2p1",
                "banner": "OpenSSH_8.2p1",
                "cves": ["CVE-2020-14145"],
            }
        ]
    }

    text = generate_management_text(BusinessRisk.CRITICAL, evaluation, technical_json=technical_json)

    # SSH-Szenario: SSH-spezifischer Text wird erwartet
    assert "SSH" in text
    assert "Port 22" in text
