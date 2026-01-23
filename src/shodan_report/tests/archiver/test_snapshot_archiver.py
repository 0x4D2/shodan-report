import json
from pathlib import Path

from shodan_report.archiver.snapshot_archiver import archive_snapshot, retrieve_archived_snapshot, list_archived_snapshots
from shodan_report.models.asset_snapshot import AssetSnapshot
from shodan_report.models.service import Service


def test_archive_and_retrieve_snapshot(tmp_path):
    # prepare snapshot
    svc = Service(port=3306, transport="tcp", product="MySQL", version="8.0.33")
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        hostnames=["host.example"],
        domains=["example.com"],
        org="TestOrg",
        isp="TestISP",
        os="Linux",
        city="City",
        country="Country",
        services=[svc],
    )

    archive_root = tmp_path / "archive"
    # write snapshot
    path = archive_snapshot(snapshot, customer_name="TestCo", month="2025-01")

    # file exists
    assert path.exists()

    # content contains expected keys
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["ip"] == "1.2.3.4"
    assert isinstance(data.get("services"), list)
    assert data["services"][0]["port"] == 3306
    assert data["services"][0]["product"] == "MySQL"

    # retrieve as AssetSnapshot
    loaded = retrieve_archived_snapshot("TestCo", "2025-01", "1.2.3.4")
    assert loaded is not None
    assert loaded.ip == "1.2.3.4"
    assert len(loaded.services) == 1
    assert loaded.services[0].port == 3306


def test_list_archived_snapshots_empty_and_nonempty(tmp_path):
    # initially empty
    assert list_archived_snapshots("NoSuchCustomer") == []

    # create one snapshot via archive_snapshot
    svc = Service(port=22, transport="tcp", product="ssh", version="7.6")
    snapshot = AssetSnapshot(
        ip="5.6.7.8",
        hostnames=[],
        domains=[],
        org="x",
        isp="y",
        os=None,
        city="",
        country="",
        services=[svc],
    )

    archive_snapshot(snapshot, customer_name="ACME", month="2025-02")
    files = list_archived_snapshots("ACME")
    assert len(files) >= 1
