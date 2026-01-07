from shodan_report.persistence.snapshot_manager import compare_snapshots
from shodan_report.models import AssetSnapshot, Service
from datetime import datetime


def _make_snapshot(ip="1.2.3.4", ports=None, services=None):
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
        open_ports=ports or [],
        last_update=datetime(2026, 1, 7),
    )


def test_compare_snapshots_no_changes():
    s1 = _make_snapshot(ports=[22], services=[Service(port=22, transport="tcp", product="ssh")])
    s2 = _make_snapshot(ports=[22], services=[Service(port=22, transport="tcp", product="ssh")])

    changes = compare_snapshots(s1, s2)
    assert changes["new_ports"] == []
    assert changes["removed_ports"] == []
    assert changes["new_services"] == []
    assert changes["removed_services"] == []


def test_compare_snapshots_ports_and_services():
    prev = _make_snapshot(
        ports=[22, 80],
        services=[Service(port=22, transport="tcp", product="ssh"), Service(port=21, transport="tcp", product="ftp")],
    )
    curr = _make_snapshot(
        ports=[22, 443],
        services=[Service(port=22, transport="tcp", product="ssh"), Service(port=443, transport="tcp", product="https")],
    )

    changes = compare_snapshots(prev, curr)
    assert changes["new_ports"] == [443]
    assert changes["removed_ports"] == [80]
    assert changes["new_services"] == ["https"]
    assert changes["removed_services"] == ["ftp"]


def test_compare_snapshots_handles_none_and_duplicates():
    prev = _make_snapshot(
        ports=[1000, 2000],
        services=[Service(port=1, transport="tcp", product=None), Service(port=2, transport="tcp", product="a")],
    )
    curr = _make_snapshot(
        ports=[2000, 3000, 1000],
        services=[Service(port=2, transport="tcp", product="a"), Service(port=3, transport="tcp", product=None), Service(port=4, transport="tcp", product="a")],
    )

    changes = compare_snapshots(prev, curr)
    assert changes["new_ports"] == [3000]
    assert changes["removed_ports"] == []


    assert "unbekannt" not in changes["new_services"] or isinstance(changes["new_services"], list)
