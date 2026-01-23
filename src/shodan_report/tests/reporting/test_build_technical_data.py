import pytest
from datetime import datetime
from shodan_report.models import AssetSnapshot, Service
from shodan_report.reporting.technical_data import build_technical_data


def _make_snapshot(
    ip: str, ports=None, services=None, last_update=None
) -> AssetSnapshot:
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
        open_ports=ports or [],  # open_ports!
        last_update=last_update or datetime.now(),
    )


def test_build_technical_data_with_services():
    services = [
        Service(port=80, transport="tcp", product="HTTP", version="1.1"),
        Service(port=443, transport="tcp", product="HTTPS", version="2.0"),
        Service(port=22, transport="tcp", product="SSH", version="8.1"),
    ]

    snapshot = _make_snapshot(
        ip="1.2.3.4",
        ports=[80, 443, 22],
        services=services,
        last_update=datetime(2024, 1, 15, 10, 30, 0),
    )

    technical = build_technical_data(snapshot)

    assert technical["ip"] == "1.2.3.4"
    assert technical["snapshot_date"] == "2024-01-15"
    assert len(technical["open_ports"]) == 3
    print(f"✓ Test passed: {len(technical['open_ports'])} open ports found")


def test_build_technical_data_without_services():
    snapshot = _make_snapshot(ip="1.2.3.4", services=[], ports=[])

    technical = build_technical_data(snapshot)

    assert technical["ip"] == "1.2.3.4"
    assert technical["open_ports"] == []
    print("Test passed: Empty services handled correctly")


def test_build_technical_data_with_raw_banner_fallback():
    snapshot = AssetSnapshot(
        ip="10.0.0.1",
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=[
            Service(
                port=8080,
                transport="tcp",
                product=None,
                version=None,
                ssl_info=None,
                ssh_info=None,
                raw={"banner": "TestBanner/1.0"},
            )
        ],
        open_ports=[8080],
        last_update=datetime(2026, 1, 7),
    )

    technical = build_technical_data(snapshot)

    assert technical["ip"] == "10.0.0.1"
    assert len(technical["open_ports"]) == 1

    assert technical["open_ports"][0]["service"]["product"] == "Unbekannter Dienst"
    assert technical["open_ports"][0]["service"]["version"] == ""


def test_build_technical_data_without_previous_snapshot():

    snapshot = _make_snapshot(
        "1.2.3.4", services=[Service(port=80, transport="tcp", product="HTTP")]
    )

    technical = build_technical_data(snapshot, None)

    assert technical["trend"] is None
    print("Test passed: trend is None without previous snapshot")


def test_build_technical_data_with_previous_metrics():
    prev_services = [
        Service(port=22, transport="tcp", product="SSH", version="8.0"),
        Service(port=3306, transport="tcp", product="MySQL", version="8.0"),
        Service(port=8443, transport="tcp", product="HTTP", version="1.1"),
    ]
    prev_snapshot = _make_snapshot(
        ip="1.2.3.4",
        ports=[22, 3306, 8443],
        services=prev_services,
        last_update=datetime(2025, 12, 15, 10, 0, 0),
    )

    curr_services = [
        Service(port=22, transport="tcp", product="SSH", version="8.1"),
        Service(port=3306, transport="tcp", product="MySQL", version="8.0"),
    ]
    snapshot = _make_snapshot(
        ip="1.2.3.4",
        ports=[22, 3306],
        services=curr_services,
        last_update=datetime(2026, 1, 20, 10, 0, 0),
    )

    technical = build_technical_data(snapshot, prev_snapshot)

    assert technical.get("previous_metrics") is not None
    prev_metrics = technical["previous_metrics"]
    assert prev_metrics["Öffentliche Ports"] == 3
    assert prev_metrics["Kritische Services"] == 2
    assert prev_metrics["TLS-Schwächen"] == 1
    assert prev_metrics["Hochrisiko-CVEs"] == 0


def test_that_open_ports_are_not_empty():
    services = [
        Service(port=80, transport="tcp", product="HTTP"),
        Service(port=443, transport="tcp", product="HTTPS"),
    ]

    snapshot = _make_snapshot("111.170.152.60", services=services)
    technical = build_technical_data(snapshot)

    assert len(technical["open_ports"]) == 2
    assert technical["open_ports"] != []
    print(f"✓ KRITISCH: {len(technical['open_ports'])} open ports, nicht leer!")


def test_simple():
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

    assert len(result["open_ports"]) == 1
