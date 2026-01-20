from shodan_report.parsing.utils import parse_shodan_host, parse_service
from shodan_report.models import AssetSnapshot, Service
from datetime import datetime


def test_parse_service_with_product_and_version():
    entry = {
        "port": 22,
        "transport": "tcp",
        "product": "OpenSSH",
        "version": "8.1p1",
        "banner": "SSH-2.0-OpenSSH_8.1p1 Ubuntu-4ubuntu4.1",
    }
    service = parse_service(entry)

    assert service.port == 22
    assert service.transport == "tcp"
    assert service.product == "OpenSSH"
    assert service.version == "8.1p1"


def test_parse_service_uses_banner_fallback():
    entry = {
        "port": 80,
        "transport": "tcp",
        "banner": "nginx/1.24.0",
    }

    service = parse_service(entry)

    assert service.product == "nginx"
    assert service.version == "1.24.0"


def test_parse_parse_shodan_host_creates_snapshot():
    shodan_data = {
        "ip_str": "1.2.3.4",
        "hostnames": ["example.com"],
        "domain": ["example.com"],
        "org": "TestOrg",
        "isp": "TestISP",
        "os": "Linux",
        "location": {"city": "Berlin", "country_name": "Germany"},
        "ports": [22, 80],
        "data": [
            {
                "port": 22,
                "transport": "tcp",
                "product": "OpenSSH",
                "version": "8.9p1",
            },
            {
                "port": 80,
                "transport": "tcp",
                "banner": "nginx 1.24.0",
            },
        ],
    }

    snapshot = parse_shodan_host(shodan_data)

    assert isinstance(snapshot, AssetSnapshot)
    assert snapshot.ip == "1.2.3.4"
    assert snapshot.city == "Berlin"
    assert snapshot.country == "Germany"
    assert len(snapshot.services) == 2
    assert snapshot.open_ports == [22, 80]


def test_parse_shodan_host_ignores_entries_without_port():
    shodan_data = {
        "ip_str": "1.2.3.4",
        "data": [
            {"banner": "invalid service"},
            {"port": 22, "transport": "tcp", "product": "OpenSSH"},
        ],
    }

    snapshot = parse_shodan_host(shodan_data)

    assert len(snapshot.services) == 1
    assert snapshot.services[0].port == 22


def test_parse_service_preserves_ssl_ssh_and_raw():
    entry = {
        "port": 443,
        "transport": "tcp",
        "product": "nginx",
        "version": "1.24.0",
        "ssl": {"cert": "dummy"},
        "ssh": {"kex": "dummy"},
    }

    service = parse_service(entry)

    assert service.raw is not None
    assert service.raw["port"] == 443
    assert service.raw["transport"] == "tcp"
    assert service.raw["product"] == "nginx"
    assert service.raw["version"] == "1.24.0"
    assert service.raw.get("ssl") == {"cert": "dummy"}
    assert service.raw.get("ssh") == {"kex": "dummy"}
    assert "_extra_info" in service.raw
    assert "_parsed_data" in service.raw


def test_parse_shodan_host_missing_fields():
    """Testet fehlende Felder in Shodan-Daten."""
    shodan_data = {
        "data": [{"port": 8080, "transport": "tcp", "banner": "example 1.0"}]
    }

    snapshot = parse_shodan_host(shodan_data)

    assert snapshot.ip in [None, ""]
    assert snapshot.city in [None, ""]
    assert snapshot.country in [None, ""]
    assert len(snapshot.services) == 1


def test_parse_shodan_host_snapshot_services_list():
    snapshot_data = {
        "ip": "217.154.224.104",
        "hostnames": ["example.local"],
        "domains": ["example.local"],
        "org": "TestOrg",
        "isp": "TestISP",
        "os": None,
        "city": "Berlin",
        "country": "Germany",
        "open_ports": [22, 443],
        "services": [
            {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.9"},
            {"port": 443, "transport": "tcp", "product": "HTTP", "version": "1.1"},
        ],
        "last_update": "2026-01-20 13:46:02.707329+00:00",
    }

    snapshot = parse_shodan_host(snapshot_data)

    assert snapshot.ip == "217.154.224.104"
    assert snapshot.city == "Berlin"
    assert snapshot.country == "Germany"
    assert snapshot.open_ports == [22, 443]
    assert len(snapshot.services) == 2


def test_parse_shodan_host_last_update_is_datetime():
    shodan_data = {"data": [{"port": 21, "transport": "tcp"}]}
    snapshot = parse_shodan_host(shodan_data)
    assert isinstance(snapshot.last_update, datetime)


def test_parse_service_sets_flags_correctly():
    entry = {
        "port": 443,
        "transport": "tcp",
        "product": "nginx",
        "version": "1.24.0",
        "ssl": {"cert": "dummy"},
        "ssh": {"kex": "dummy"},
        "vpn_protected": True,
        "tunneled": True,
        "cert_required": True,
    }

    service = parse_service(entry)

    assert service.is_encrypted is True
    assert service.requires_auth is True
    assert service.vpn_protected is True
    assert service.tunneled is True
    assert service.cert_required is True
