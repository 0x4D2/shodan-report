from datetime import datetime
import pytest

from shodan_report.reporting.trend import analyze_trend
from shodan_report.models import AssetSnapshot, Service


def make_snapshot(ip: str, ports=None, services=None):
    ports = ports or []
    services = services or []
    return AssetSnapshot(
        ip=ip,
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=services,
        open_ports=ports,
        last_update=datetime(2026, 1, 7),
    )


def test_analyze_trend_new_and_removed_ports_and_services(monkeypatch):
    monkeypatch.setattr(
        "shodan_report.reporting.trend.compare_snapshots",
        lambda prev, curr: {
            "new_ports": [443],
            "removed_ports": [80],
            "new_services": ["https"],
            "removed_services": [],
        },
    )

    prev = make_snapshot(
        "1.2.3.4",
        ports=[22, 80],
        services=[Service(port=22, transport="tcp", product="ssh", version="8.1")],
    )
    current = make_snapshot(
        "1.2.3.4",
        ports=[22, 443],
        services=[
            Service(port=22, transport="tcp", product="ssh", version="8.1"),
            Service(port=443, transport="tcp", product="https", version="1.0"),
        ],
    )

    trend = analyze_trend(prev, current)
    assert "Neue offene Ports: 443" in trend
    assert "Geschlossene Ports: 80" in trend
    assert "Neu entdeckte Dienste: https" in trend
    assert "Entfernte Dienste: ssh" not in trend


def test_analyze_trend_no_changes(monkeypatch):
    monkeypatch.setattr(
        "shodan_report.reporting.trend.compare_snapshots",
        lambda prev, curr: {
            "new_ports": [],
            "removed_ports": [],
            "new_services": [],
            "removed_services": [],
        },
    )

    snapshot = make_snapshot(
        "1.2.3.4",
        ports=[22],
        services=[Service(port=22, transport="tcp", product="ssh", version="8.1")],
    )
    trend = analyze_trend(snapshot, snapshot)
    assert (
        trend
        == "Keine signifikanten Veränderungen im Vergleich zum vorherigen Snapshot."
    )


def test_analyze_trend_removed_service(monkeypatch):
    monkeypatch.setattr(
        "shodan_report.reporting.trend.compare_snapshots",
        lambda prev, curr: {
            "new_ports": [],
            "removed_ports": [22],
            "new_services": [],
            "removed_services": ["ssh"],
        },
    )

    prev = make_snapshot(
        "1.2.3.4",
        ports=[22],
        services=[Service(port=22, transport="tcp", product="ssh", version="8.1")],
    )
    current = make_snapshot("1.2.3.4", ports=[], services=[])
    trend = analyze_trend(prev, current)
    assert "Geschlossene Ports: 22" in trend
    assert "Entfernte Dienste: ssh" in trend


def test_analyze_trend_order_and_format(monkeypatch):
    monkeypatch.setattr(
        "shodan_report.reporting.trend.compare_snapshots",
        lambda prev, curr: {
            "new_ports": [8080, 443],
            "removed_ports": [],
            "new_services": [],
            "removed_services": [],
        },
    )

    prev = make_snapshot("1.2.3.4")
    curr = make_snapshot("1.2.3.4", ports=[8080, 443])
    trend = analyze_trend(prev, curr)
    assert "Neue offene Ports: 8080, 443" in trend


def test_analyze_trend_handles_empty_service_name(monkeypatch):
    monkeypatch.setattr(
        "shodan_report.reporting.trend.compare_snapshots",
        lambda prev, curr: {
            "new_ports": [],
            "removed_ports": [],
            "new_services": [""],
            "removed_services": [],
        },
    )

    prev = make_snapshot("1.2.3.4")
    curr = make_snapshot("1.2.3.4")
    trend = analyze_trend(prev, curr)
    assert "Neu entdeckte Dienste:" in trend
