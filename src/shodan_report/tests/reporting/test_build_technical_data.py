import pytest
from datetime import datetime
from shodan_report.models import AssetSnapshot, Service
from shodan_report.reporting.technical_data import build_technical_data


def _make_snapshot(ip: str, ports=None, services=None, last_update=None) -> AssetSnapshot:
    return AssetSnapshot(
        ip=ip,
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=services or [],
        open_ports=ports or [],  # Hier heißt es open_ports!
        last_update=last_update or datetime.now(),
    )


def test_build_technical_data_with_services():
    # Arrange: Snapshot mit Services erstellen
    services = [
        Service(port=80, transport="tcp", product="HTTP", version="1.1"),
        Service(port=443, transport="tcp", product="HTTPS", version="2.0"),
        Service(port=22, transport="tcp", product="SSH", version="8.1"),
    ]
    
    snapshot = _make_snapshot(
        ip="1.2.3.4",
        ports=[80, 443, 22],
        services=services,
        last_update=datetime(2024, 1, 15, 10, 30, 0)
    )
    
    technical = build_technical_data(snapshot)
    
    assert technical["ip"] == "1.2.3.4"
    assert technical["snapshot_date"] == "2024-01-15"
    assert len(technical["open_ports"]) == 3
    print(f"✓ Test passed: {len(technical['open_ports'])} open ports found")


def test_build_technical_data_without_services():
    # Arrange: Snapshot OHNE Services
    snapshot = _make_snapshot(ip="1.2.3.4", services=[], ports=[])
    
    # Act
    technical = build_technical_data(snapshot)
    
    # Assert
    assert technical["ip"] == "1.2.3.4"
    assert technical["open_ports"] == []
    print("✓ Test passed: Empty services handled correctly")


def test_build_technical_data_with_raw_banner_fallback():
    service_with_banner = Service(
        port=8080, 
        transport="tcp", 
        product=None,
        version=None,
        raw={"banner": "Apache/2.4.41"}  # Banner in raw!
    )
    
    snapshot = _make_snapshot(
        ip="5.6.7.8",
        services=[service_with_banner]
    )
    
    # Act
    technical = build_technical_data(snapshot)
    
    # Assert: Sollte "unbekannt" verwenden, da product None
    assert len(technical["open_ports"]) == 1
    assert technical["open_ports"][0]["port"] == 8080
    assert technical["open_ports"][0]["service"]["product"] == "unbekannt"
    print("✓ Test passed: banner fallback works")


def test_build_technical_data_without_previous_snapshot():
    """Testet, dass trend None bleibt ohne previous snapshot."""
    # Arrange
    snapshot = _make_snapshot(
        "1.2.3.4", 
        services=[Service(port=80, transport="tcp", product="HTTP")]
    )
    
    # Act: Ohne previous snapshot
    technical = build_technical_data(snapshot, None)
    
    # Assert
    assert technical["trend"] is None
    print("✓ Test passed: trend is None without previous snapshot")


def test_that_open_ports_are_not_empty():
    """KRITISCHER TEST: Muss zeigen, dass open_ports NICHT leer sind!"""
    services = [
        Service(port=80, transport="tcp", product="HTTP"),
        Service(port=443, transport="tcp", product="HTTPS"),
    ]
    
    snapshot = _make_snapshot("111.170.152.60", services=services)
    technical = build_technical_data(snapshot)
    
    # DAS ist die kritische Assertion:
    assert len(technical["open_ports"]) == 2  # Muss 2 sein!
    assert technical["open_ports"] != []  # Darf nicht leer sein!
    print(f"✓ KRITISCH: {len(technical['open_ports'])} open ports, nicht leer!")
    

def test_simple():
    """Einfachster Test als Basis-Line."""
    snapshot = AssetSnapshot(
        ip="test",
        services=[Service(port=1234, transport="tcp", product="TEST")],
        open_ports=[1234],
        last_update=None,
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
    )
    
    result = build_technical_data(snapshot)
    
    print(f"\n=== Einfacher Test ===")
    print(f"IP: {result['ip']}")
    print(f"Open ports count: {len(result['open_ports'])}")
    print(f"Open ports: {result['open_ports']}")
    
    assert len(result['open_ports']) == 1


if __name__ == "__main__":
    print("=== Tests für build_technical_data ===")
    
    test_simple()
    test_build_technical_data_with_services()
    test_build_technical_data_without_services()
    test_build_technical_data_with_raw_banner_fallback()
    test_build_technical_data_without_previous_snapshot()
    test_that_open_ports_are_not_empty()
    
    print("\n✅ Alle Tests bestanden - build_technical_data() funktioniert!")