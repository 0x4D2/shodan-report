from datetime import datetime, timezone
import pytest
from shodan_report.models import Service, AssetSnapshot
from shodan_report.evaluation.evaluation import evaluate_snapshot, RiskLevel
from shodan_report.evaluation.risk_prioritization import prioritize_risk, BusinessRisk

def make_snapshot_with_services(open_ports_count=2, include_critical_service=False):
    services = []

    for i in range(open_ports_count):
        services.append(
            Service(
                port=20 + i,
                transport="tcp",
                product="nginx",
                version="1.24.0",
                raw={}
            )
        )

    if include_critical_service:
        services.append(
            Service(
                port=22,
                transport="tcp",
                product="ssh",
                version="8.1p1",
                raw={}
            )
        )

    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        hostnames=[],
        domains=[],
        org="TestOrg",
        isp="TestISP",
        os="Linux",
        city="Berlin",
        country="Germany",
        services=services,
        open_ports=list(range(20, 20 + open_ports_count)),
        last_update=datetime(2026, 1, 7)
    )
    return snapshot


def test_evaluate_snapshot_low_risk():
    snapshot = make_snapshot_with_services(open_ports_count=1)
    evaluation = evaluate_snapshot(snapshot)
    assert evaluation.risk == RiskLevel.LOW
    assert evaluation.critical_points == []


def test_evaluate_snapshot_medium_risk():
    snapshot = make_snapshot_with_services(open_ports_count=5)
    evaluation = evaluate_snapshot(snapshot)
    assert evaluation.risk == RiskLevel.MEDIUM
    assert any("Mehrere offene Dienste" in pt for pt in evaluation.critical_points)


def test_evaluate_snapshot_high_risk():
    snapshot = make_snapshot_with_services(open_ports_count=12)
    evaluation = evaluate_snapshot(snapshot)
    assert evaluation.risk == RiskLevel.HIGH
    assert any("Viele offene Dienste" in pt for pt in evaluation.critical_points)


def test_evaluate_snapshot_with_critical_service():
    snapshot = make_snapshot_with_services(open_ports_count=2, include_critical_service=True)
    evaluation = evaluate_snapshot(snapshot)
    assert any("Kritischer Dienst gefunden" in pt for pt in evaluation.critical_points)
    assert evaluation.risk == RiskLevel.HIGH or evaluation.risk == RiskLevel.MEDIUM  # je nach Anzahl anderer Ports


def test_prioritize_risk_monitor():
    snapshot = make_snapshot_with_services(open_ports_count=1)
    evaluation = evaluate_snapshot(snapshot)
    risk = prioritize_risk(evaluation)
    assert risk == BusinessRisk.MONITOR


def test_prioritize_risk_attention():
    snapshot = make_snapshot_with_services(open_ports_count=5)
    evaluation = evaluate_snapshot(snapshot)
    risk = prioritize_risk(evaluation)
    assert risk == BusinessRisk.ATTENTION


def test_prioritize_risk_critical_due_to_high_risk():
    snapshot = make_snapshot_with_services(open_ports_count=12)
    evaluation = evaluate_snapshot(snapshot)
    risk = prioritize_risk(evaluation)
    assert risk == BusinessRisk.CRITICAL


def test_prioritize_risk_critical_due_to_critical_service():
    snapshot = make_snapshot_with_services(open_ports_count=2, include_critical_service=True)
    evaluation = evaluate_snapshot(snapshot)
    risk = prioritize_risk(evaluation)
    assert risk == BusinessRisk.CRITICAL


@pytest.mark.parametrize("num_ports,expected_risk", [
    (0, RiskLevel.LOW),
    (3, RiskLevel.MEDIUM),   # Schwelle für mehrere offene Dienste
    (5, RiskLevel.MEDIUM),
    (11, RiskLevel.HIGH),    # Schwelle für viele offene Dienste
])
def test_open_ports_risk_levels(num_ports, expected_risk):
    services = [Service(port=i+1, transport="tcp", product="test", version="1.0") for i in range(num_ports)]
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=services,
        open_ports=list(range(1, num_ports+1)),
        last_update=datetime.now(timezone.utc)

    )

    eval_result = evaluate_snapshot(snapshot)
    assert eval_result.risk == expected_risk


def test_critical_service_triggers_business_risk():
    services = [
        Service(port=22, transport="tcp", product="ssh", version="8.1p1"),
        Service(port=80, transport="tcp", product="nginx", version="1.24.0")
    ]
    snapshot = AssetSnapshot(
        ip="5.6.7.8",
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=services,
        open_ports=[22, 80],
        last_update=datetime.now(timezone.utc)

    )

    eval_result = evaluate_snapshot(snapshot)
    business_risk = prioritize_risk(eval_result)
    assert business_risk == BusinessRisk.CRITICAL
    assert any("Kritischer Dienst gefunden" in pt for pt in eval_result.critical_points)


def test_evaluate_snapshot_with_no_services():
    snapshot = AssetSnapshot(
        ip="9.9.9.9",
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=[],
        open_ports=[],
        last_update=datetime.now(timezone.utc)
    )
    eval_result = evaluate_snapshot(snapshot)
    business_risk = prioritize_risk(eval_result)

    assert eval_result.risk == RiskLevel.LOW
    assert eval_result.critical_points == []
    assert business_risk == BusinessRisk.MONITOR


def test_vulnerable_versions_detected():
    services = [
        Service(port=21, transport="tcp", product="ftp", version="1.0"),
        Service(port=22, transport="tcp", product="ssh", version="8.1p1")
    ]
    snapshot = AssetSnapshot(
        ip="8.8.8.8",
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=services,
        open_ports=[21, 22],
        last_update=datetime.now(timezone.utc)
    )
    eval_result = evaluate_snapshot(snapshot)
    assert any("Veraltete/anfällige Version" in pt for pt in eval_result.critical_points)
