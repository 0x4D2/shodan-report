from pathlib import Path
import json
from datetime import datetime
import pytest

from shodan_report.models import AssetSnapshot, Service
from shodan_report.archiver import archive_snapshot, list_archived_snapshots, retrieve_archived_snapshot

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

def test_archive_and_list(tmp_path, monkeypatch):
    monkeypatch.setattr("shodan_report.archiver.ARCHIVE_DIR", tmp_path / "archive")
    
    snapshot = _make_snapshot(
        ports=[22, 80],
        services=[Service(port=22, transport="tcp", product="ssh"), Service(port=80, transport="tcp", product="http")]
    )
    
    path = archive_snapshot(snapshot, "TestCustomer", "2026-01")
    
    # Datei existiert
    assert path.exists()
    
    files = list_archived_snapshots("TestCustomer")
    assert len(files) == 1
    assert files[0].name == path.name

def test_retrieve_existing_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr("shodan_report.archiver.ARCHIVE_DIR", tmp_path / "archive")
    
    snapshot = _make_snapshot(ip="5.6.7.8")
    archive_snapshot(snapshot, "CustomerX", "2026-01")
    
    loaded = retrieve_archived_snapshot("CustomerX", "2026-01", "5.6.7.8")
    assert loaded.ip == snapshot.ip
    assert loaded.open_ports == snapshot.open_ports

def test_retrieve_nonexistent_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr("shodan_report.archiver.ARCHIVE_DIR", tmp_path / "archive")
    
    loaded = retrieve_archived_snapshot("NoCustomer", "2026-01", "1.1.1.1")
    assert loaded is None

def test_services_serialized_correctly(tmp_path, monkeypatch):
    monkeypatch.setattr("shodan_report.archiver.ARCHIVE_DIR", tmp_path / "archive")
    
    snapshot = _make_snapshot(
        ip="8.8.8.8",
        services=[Service(port=22, transport="tcp", product=None, version=None)]
    )
    
    archive_snapshot(snapshot, "CustomerY", "2026-01")
    path = tmp_path / "archive" / "CustomerY" / "2026-01_8.8.8.8.json"
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    
    assert data["services"][0]["product"] == "unbekannt"
    assert data["services"][0]["version"] == "unbekannt"
