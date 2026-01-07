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
    entry ={
        "port": 80,
        "transport": "tcp",
        "banner": "nginx/1.24.0",
    }

    service = parse_service(entry)

    assert service.product == "nginx"
    assert service.version == "1.24.0"


# def test_parse_service_without_product_and_version():
#     entry = {
#         "port": 443,
#         "transport": "tcp",
#         "banner": "Apache",
#     }

#     service = parse_service(entry)

#     assert service.port == 443
#     assert service.transport == "tcp"
#     assert service.product == "Apache/2.4.41"
#     assert service.version is None


def test_parse_parse_shodan_host_creates_snapshot():
        shodan_data = {
            "ip_str": "1.2.3.4",
            "hostnames": ["example.com"],
            "domain": ["example.com"],
            "org": "TestOrg",
            "isp": "TestISP",
            "os": "Linux",
            "location": {
                "city": "Berlin",
                "country_name": "Germany"
            },
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
                }
            ]
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
            ]
        }

        snapshot = parse_shodan_host(shodan_data)

        assert len(snapshot.services) == 1
        assert snapshot.services[0].port == 22


# def test_parse_service_banner_slash_format():
#         entry = {
#             "port": 80,
#             "transport": "tcp",
#             "banner": "nginx/1.24.0",
#         }

#         service = parse_service(entry)

#         # Erwartung: Produkt und Version aus Slash‑Format getrennt
#         assert service.product == "nginx"
#         assert service.version == "1.24.0"


# def test_parse_service_openssh_underscore_format():
#         entry = {
#             "port": 22,
#             "transport": "tcp",
#             "banner": "OpenSSH_8.1p1",
#         }

#         service = parse_service(entry)

#         assert service.product == "OpenSSH"
#         assert service.version == "8.1p1"


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

        assert service.ssl_info == {"cert": "dummy"}
        assert service.ssh_info == {"kex": "dummy"}
        assert service.raw == entry


def test_parse_shodan_host_missing_fields():
        shodan_data = {
            # kein ip_str, keine location
            "data": [
                {"port": 8080, "transport": "tcp", "banner": "example 1.0"}
            ]
        }

        snapshot = parse_shodan_host(shodan_data)

        assert snapshot.ip is None
        assert snapshot.city is None
        assert snapshot.country is None
        assert len(snapshot.services) == 1


def test_parse_shodan_host_last_update_is_datetime():
        shodan_data = {"data": [{"port": 21, "transport": "tcp"}]}
        snapshot = parse_shodan_host(shodan_data)
        assert isinstance(snapshot.last_update, datetime)

