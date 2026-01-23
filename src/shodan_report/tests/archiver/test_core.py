# test_core.py
from pathlib import Path
import pytest
from shodan_report.archiver.core import (
    archive_snapshot,
    retrieve_archived_snapshot,
    ARCHIVE_DIR,
    list_archived_snapshots,
)
from shodan_report.models import AssetSnapshot, Service
from datetime import datetime


def make_snapshot():
    return AssetSnapshot(
        ip="1.2.3.4",
        hostnames=["test.example.com"],
        domains=["example.com"],
        org="Test Org",
        isp="Test ISP",
        os="Linux 4.4",
        city="Test City",
        country="DE",
        services=[Service(port=22, transport="tcp", product="ssh", version="2.0")],
        open_ports=[22, 80],
        last_update=datetime.now(),
        raw_banner=[],
        ssl_info=None,
        ssh_info=None,
    )


def make_minimal_snapshot(ip="1.2.3.4"):
    """Minimal snapshot for testing"""
    return AssetSnapshot(
        ip=ip,
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=[],
        open_ports=[],
        last_update=datetime.now(),
        raw_banner=[],
        ssl_info=None,
        ssh_info=None,
    )


def test_archive_and_retrieve_snapshot(tmp_path, monkeypatch):
    # Temporären Archivordner einrichten
    archive_test_dir = tmp_path / "archive"
    archive_test_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("shodan_report.archiver.core.ARCHIVE_DIR", archive_test_dir)

    # Snapshot erstellen und archivieren
    snapshot = make_snapshot()
    saved_path = archive_snapshot(snapshot, "TestCustomer", "2026-01")

    # Prüfen, ob die Datei existiert
    assert saved_path.exists()
    assert saved_path.name == "2026-01_1.2.3.4.json"

    # Snapshot abrufen
    retrieved = retrieve_archived_snapshot("TestCustomer", "2026-01", "1.2.3.4")

    # Prüfen, ob die Daten korrekt geladen wurden
    assert retrieved is not None
    assert retrieved.ip == snapshot.ip
    assert retrieved.hostnames == snapshot.hostnames
    assert retrieved.domains == snapshot.domains
    assert retrieved.services[0].port == snapshot.services[0].port
    assert retrieved.services[0].product == snapshot.services[0].product


def test_list_archived_snapshots(tmp_path, monkeypatch):
    archive_test_dir = tmp_path / "archive"
    archive_test_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("shodan_report.archiver.core.ARCHIVE_DIR", archive_test_dir)

    snapshot1 = make_minimal_snapshot("1.2.3.4")
    snapshot2 = make_minimal_snapshot("5.6.7.8")

    archive_snapshot(snapshot1, "TestCustomer", "2026-01")
    archive_snapshot(snapshot2, "TestCustomer", "2026-01")

    snapshots = list_archived_snapshots("TestCustomer")
    assert len(snapshots) == 2
    filenames = [p.name for p in snapshots]
    assert "2026-01_1.2.3.4.json" in filenames
    assert "2026-01_5.6.7.8.json" in filenames


def test_retrieve_nonexistent_snapshot(tmp_path, monkeypatch):
    archive_test_dir = tmp_path / "archive"
    archive_test_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("shodan_report.archiver.core.ARCHIVE_DIR", archive_test_dir)

    result = retrieve_archived_snapshot("TestCustomer", "2026-01", "9.9.9.9")
    assert result is None
