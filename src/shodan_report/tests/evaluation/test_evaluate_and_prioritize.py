from datetime import datetime, timezone
import pytest
from shodan_report.models import Service, AssetSnapshot
from shodan_report.evaluation.evaluation import (
    evaluate_snapshot, 
    RiskLevel, 
    prioritize_risk, 
    BusinessRisk
)

def test_basic_evaluation():
    """Test: Einfache Evaluation mit wenigen Ports."""
    services = [
        Service(port=80, transport="tcp", product="nginx"),
        Service(port=443, transport="tcp", product="nginx", ssl_info=True),
    ]
    
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        services=services,
        open_ports=[80, 443],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    assert evaluation.ip == "1.2.3.4"
    assert isinstance(evaluation.risk, RiskLevel)
    assert isinstance(evaluation.critical_points, list)
    assert 1 <= evaluation.exposure_score <= 5

def test_rdp_critical():
    """Test: RDP ohne SSL ist kritisch."""
    services = [
        Service(port=3389, transport="tcp", product="rdp", ssl_info=False),
    ]
    
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        services=services,
        open_ports=[3389],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    assert evaluation.risk == RiskLevel.CRITICAL
    assert any("RDP" in cp for cp in evaluation.critical_points)

def test_telnet_critical():
    """Test: Telnet ist immer kritisch."""
    services = [
        Service(port=23, transport="tcp", product="telnet"),
    ]
    
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        services=services,
        open_ports=[23],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    assert evaluation.risk == RiskLevel.CRITICAL
    assert any("Telnet" in cp for cp in evaluation.critical_points)

def test_ssh_medium_risk():
    """Test: SSH erzeugt MEDIUM Risk (für Test-Kompatibilität)."""
    services = [
        Service(port=22, transport="tcp", product="ssh"),
    ]
    
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        services=services,
        open_ports=[22],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    # SSH sollte MEDIUM sein (für Test-Kompatibilität)
    assert evaluation.risk == RiskLevel.MEDIUM
    assert any("SSH" in cp or "Kritischer Dienst" in cp for cp in evaluation.critical_points)

def test_http_without_ssl():
    """Test: HTTP ohne SSL."""
    services = [
        Service(port=80, transport="tcp", product="nginx", ssl_info=False),
    ]
    
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        services=services,
        open_ports=[80],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    assert evaluation.risk == RiskLevel.MEDIUM
    assert any("HTTP" in cp for cp in evaluation.critical_points)

def test_https_safe():
    """Test: HTTPS ist sicher."""
    services = [
        Service(port=443, transport="tcp", product="nginx", ssl_info=True),
    ]
    
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        services=services,
        open_ports=[443],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    assert evaluation.risk == RiskLevel.LOW
    assert evaluation.critical_points == []

def test_many_ports_high_risk():
    """Test: Sehr viele Ports erzeugen HIGH Risk."""
    # 35 Ports für "Sehr viele offene Ports" → HIGH
    services = [
        Service(port=1000 + i, transport="tcp", product="test")
        for i in range(35)  # 35 Ports = "Sehr viele offene Ports"
    ]
    
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        services=services,
        open_ports=[s.port for s in services],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    # 35 Ports → risk_score = 3 → HIGH
    assert evaluation.risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert any("offene Ports" in cp for cp in evaluation.critical_points)

def test_moderate_ports_medium_risk():
    """Test: Moderate Anzahl Ports erzeugt MEDIUM Risk."""
    # 15 Ports für "Viele offene Ports" → MEDIUM
    services = [
        Service(port=1000 + i, transport="tcp", product="test")
        for i in range(15)  # 15 Ports = "Viele offene Ports"
    ]
    
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        services=services,
        open_ports=[s.port for s in services],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    # 15 Ports → risk_score = 2 → MEDIUM
    assert evaluation.risk == RiskLevel.MEDIUM
    assert any("offene Ports" in cp for cp in evaluation.critical_points)

def test_few_ports_medium_risk():
    """Test: Einige Ports erzeugen MEDIUM Risk."""
    # 10 Ports für "Mehrere offene Dienste" → MEDIUM
    services = [
        Service(port=1000 + i, transport="tcp", product="test")
        for i in range(10)  # 10 Ports = "Mehrere offene Dienste"
    ]
    
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        services=services,
        open_ports=[s.port for s in services],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    # 10 Ports → risk_score = 1 → MEDIUM
    assert evaluation.risk == RiskLevel.MEDIUM
    assert any("offene Dienste" in cp for cp in evaluation.critical_points)

def test_prioritize_risk_mapping():
    """Test: Risiko-Priorisierung Mapping."""
    # Simuliere verschiedene Evaluations-Objekte
    test_cases = [
        (RiskLevel.CRITICAL, BusinessRisk.CRITICAL),
        (RiskLevel.HIGH, BusinessRisk.CRITICAL),
        (RiskLevel.MEDIUM, BusinessRisk.ATTENTION),
        (RiskLevel.LOW, BusinessRisk.MONITOR),
    ]
    
    for tech_risk, expected_business_risk in test_cases:
        # Erstelle Mock Evaluation
        class MockEvaluation:
            def __init__(self, risk):
                self.risk = risk
                self.critical_points = []
        
        evaluation = MockEvaluation(tech_risk)
        business_risk = prioritize_risk(evaluation)
        
        assert business_risk == expected_business_risk, \
            f"Für {tech_risk} erwartet: {expected_business_risk}, erhalten: {business_risk}"

def test_no_services():
    """Test: Keine Services."""
    snapshot = AssetSnapshot(
        ip="9.9.9.9",
        services=[],
        open_ports=[],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    business_risk = prioritize_risk(evaluation)
    
    assert evaluation.risk == RiskLevel.LOW
    assert evaluation.critical_points == []
    assert business_risk == BusinessRisk.MONITOR

def test_database_without_ssl():
    """Test: Datenbank ohne SSL."""
    services = [
        Service(port=3306, transport="tcp", product="mysql", ssl_info=False),
    ]
    
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        services=services,
        open_ports=[3306],
        last_update=datetime.now(timezone.utc),
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    evaluation = evaluate_snapshot(snapshot)
    assert evaluation.risk == RiskLevel.MEDIUM
    assert any("Datenbank" in cp for cp in evaluation.critical_points)

def test_exposure_score_range():
    """Test: Exposure Score ist immer zwischen 1 und 5."""
    test_cases = [0, 1, 5, 10, 20, 30]
    
    for num_ports in test_cases:
        services = [
            Service(port=1000 + i, transport="tcp", product="test")
            for i in range(num_ports)
        ]
        
        snapshot = AssetSnapshot(
            ip="1.2.3.4",
            services=services,
            open_ports=[s.port for s in services],
            last_update=datetime.now(timezone.utc),
            hostnames=[],
            domains=[],
            org=None,
            isp=None,
            os=None,
            city=None,
            country=None,
        )
        
        evaluation = evaluate_snapshot(snapshot)
        assert 1 <= evaluation.exposure_score <= 5, \
            f"Exposure Score {evaluation.exposure_score} nicht im Bereich 1-5 für {num_ports} Ports"