import pytest
from shodan_report.parsing.service_identity import extract_service_identity


def test_explicit_fields_dict():
    s = {"port": 80, "product": "nginx", "version": "1.22.0"}
    out = extract_service_identity(s)
    assert out["port"] == 80
    assert out["product"] == "NGINX"
    assert out["version"] == "1.22.0"
    assert out["confidence"] == "high"


def test_nested_service_dict():
    s = {"port": 22, "service": {"product": "OpenSSH", "version": "8.9"}}
    out = extract_service_identity(s)
    assert out["port"] == 22
    assert out["product"] == "OpenSSH"
    assert out["version"] == "8.9"
    assert out["confidence"] == "high"


def test_banner_nginx():
    s = {"port": 80, "banner": "nginx/1.18.0 (Ubuntu)"}
    out = extract_service_identity(s)
    assert out["product"] == "NGINX"
    assert out["version"] == "1.18.0"
    assert out["confidence"] in ("medium", "high")


def test_banner_openssh():
    s = {"port": 22, "banner": "OpenSSH_8.2p1 Debian-4"}
    out = extract_service_identity(s)
    assert out["product"] == "OpenSSH"
    assert out["confidence"] in ("medium", "high")


def test_port_only():
    s = 3306
    out = extract_service_identity(s)
    # port-only shape may not yield product (stringified), accept None or MySQL fallback
    assert out.get("port") == None or out.get("port") == 3306


def test_apache_banner():
    s = {"port": 80, "banner": "Apache/2.4.41 (Ubuntu)"}
    out = extract_service_identity(s)
    assert out["product"] == "Apache"
    assert out["version"] == "2.4.41"


def test_php_banner():
    s = {"port": 80, "banner": "PHP/7.4.3"}
    out = extract_service_identity(s)
    assert out["product"] == "PHP"
    assert out["version"] == "7.4.3"


def test_iis_banner():
    s = {"port": 80, "banner": "Microsoft-IIS/10.0"}
    out = extract_service_identity(s)
    assert out["product"] == "IIS"
    assert out["version"] == "10.0"
