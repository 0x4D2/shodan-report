from datetime import datetime, timezone

from shodan_report.models import Service
from shodan_report.evaluation.helpers.eval_helpers import (
    analyze_open_ports,
    analyze_services,
)


def test_analyze_open_ports_thresholds():
    # 15 Ports => 'Viele offene Ports' (score 2)
    services = [Service(port=1000 + i, transport="tcp", product="test") for i in range(15)]
    score, findings = analyze_open_ports(services)
    assert score == 2
    assert any("Viele offene Ports" in f for f in findings)

    # 10 Ports => 'Mehrere offene Dienste' (score 1)
    services = [Service(port=2000 + i, transport="tcp", product="test") for i in range(10)]
    score, findings = analyze_open_ports(services)
    assert score == 1
    assert any("Mehrere offene Dienste" in f for f in findings)


def test_analyze_services_detects_critical_and_versions():
    services = [
        Service(port=3389, transport="tcp", product="rdp", ssl_info=False),
        Service(port=22, transport="tcp", product="ssh", ssl_info=False),
        Service(port=80, transport="tcp", product="http", ssl_info=False, version="1.0"),
    ]

    score, findings = analyze_services(services)

    # Expected scoring:
    # RDP without SSL = 3, SSH = 2, HTTP without SSL = 1, version '1.0' = +1 => total 7
    assert score == 7
    assert any("RDP" in f for f in findings)
    assert any("Kritischer Dienst gefunden: SSH" in f for f in findings)
    assert any("HTTP ohne Verschlüsselung" in f for f in findings)
    assert any("Veraltete/anfällige Version" in f for f in findings)
