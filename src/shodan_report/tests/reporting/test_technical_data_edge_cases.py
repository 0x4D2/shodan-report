"""Edge-Case-Tests für reporting/technical_data.py."""
import pytest
from datetime import datetime
from shodan_report.models import AssetSnapshot, Service
from shodan_report.reporting.technical_data import (
    build_technical_data,
    _classify_service_type,
    _identify_critical_services,
    _identify_vulnerable_versions,
)


def _snap(services, ip="1.2.3.4"):
    return AssetSnapshot(
        ip=ip,
        services=services,
        open_ports=[s.port for s in services] if services else [],
        last_update=datetime(2026, 1, 1),
        hostnames=[], domains=[], org=None, isp=None,
        os=None, city=None, country=None,
    )


# ── services=None Guard ───────────────────────────────────────────────────────

def test_build_technical_data_services_none():
    """snapshot.services=None darf keinen TypeError werfen."""
    snap = _snap([])
    snap.services = None
    result = build_technical_data(snap)
    assert result["open_ports"] == []
    assert result["services"] == []


# ── extra_info=None in raw ────────────────────────────────────────────────────

def test_identify_critical_services_extra_info_none():
    """extra_info=None darf keinen AttributeError in .lower() werfen."""
    port_infos = [{"port": 53, "extra_info": None, "is_ssl": False}]
    result = _identify_critical_services(port_infos)
    assert isinstance(result, list)


def test_build_technical_data_raw_extra_info_none():
    """Service mit raw={"_extra_info": None} darf build_technical_data nicht crashen."""
    svc = Service(port=53, transport="tcp", product="DNS",
                  raw={"_extra_info": None, "_parsed_data": "", "_certificate_info": ""})
    result = build_technical_data(_snap([svc]))
    assert len(result["open_ports"]) == 1


# ── _classify_service_type ────────────────────────────────────────────────────

@pytest.mark.parametrize("port,expected", [
    (53,    "dns"),
    (80,    "web"),
    (443,   "web"),
    (8080,  "web"),
    (8443,  "web"),
    (22,    "ssh"),
    (21,    "ftp"),
    (20,    "ftp"),
    (23,    "telnet"),
    (25,    "smtp"),
    (3306,  "database"),
    (5432,  "database"),
    (27017, "database"),
    (1433,  "database"),
    (445,   "fileshare"),
    (139,   "fileshare"),
    (9999,  "other"),
])
def test_classify_service_type(port, expected):
    svc = Service(port=port, transport="tcp", product="test")
    assert _classify_service_type(svc) == expected


# ── _identify_critical_services ───────────────────────────────────────────────

def test_identify_critical_services_dns_recursion():
    infos = [{"port": 53, "extra_info": "recursion enabled", "is_ssl": False}]
    result = _identify_critical_services(infos)
    assert any(r["port"] == 53 for r in result)
    assert any("Recursion" in r["reason"] or "recursion" in r["reason"].lower() for r in result)


def test_identify_critical_services_dns_no_recursion():
    infos = [{"port": 53, "extra_info": "", "is_ssl": False}]
    result = _identify_critical_services(infos)
    assert not any(r["port"] == 53 for r in result)


def test_identify_critical_services_database_ports():
    for port in [3306, 5432, 27017, 1433]:
        infos = [{"port": port, "extra_info": "", "is_ssl": False}]
        result = _identify_critical_services(infos)
        assert any(r["port"] == port for r in result), f"Port {port} nicht als kritisch erkannt"


def test_identify_critical_services_ssh_unencrypted():
    infos = [{"port": 22, "extra_info": "", "is_ssl": False}]
    result = _identify_critical_services(infos)
    assert any(r["port"] == 22 for r in result)


def test_identify_critical_services_empty():
    assert _identify_critical_services([]) == []


# ── _identify_vulnerable_versions ─────────────────────────────────────────────

@pytest.mark.parametrize("version,should_flag", [
    ("old-1.2",       True),
    ("1.2-deprecated", True),
    ("test-build",    True),
    ("dev-snapshot",  True),
    ("8.0.28",        False),
    ("",              False),
])
def test_identify_vulnerable_versions(version, should_flag):
    infos = [{"port": 80, "service": {"product": "nginx", "version": version}}]
    result = _identify_vulnerable_versions(infos)
    if should_flag:
        assert len(result) == 1, f"Version '{version}' sollte als vulnerable erkannt werden"
    else:
        assert len(result) == 0, f"Version '{version}' sollte nicht als vulnerable gelten"


def test_identify_vulnerable_versions_empty():
    assert _identify_vulnerable_versions([]) == []
