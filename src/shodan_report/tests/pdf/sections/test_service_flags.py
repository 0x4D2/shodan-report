import pytest

from shodan_report.pdf.sections.management import _build_service_flags


def test_build_service_flags_basic():
    technical_json = {
        "services": [
            {"port": 22, "product": "OpenSSH", "version": "8.9p1 Ubuntu 3ubuntu0.13"},
            {"port": 80, "product": "HTTP", "version": "1.1 200 OK Server: nginx"},
            {"port": 443, "product": "HTTP", "version": "1.1 200 OK Server: nginx"},
        ],
        "ssl_info": None,
    }

    flags = _build_service_flags(technical_json)

    assert any("Port 22" in f and "SSH" in f for f in flags)
    assert any("Port 80" in f and "HTTP" in f for f in flags)
    assert any("Port 443" in f and "HTTPS" in f or "Zertifikat" in f or "ssl_info" in f for f in flags)


def test_build_service_flags_dedup_and_limit():
    # create many distinct services to test dedup/limit
    services = [{"port": i, "product": f"svc{i}", "version": "v1"} for i in range(1, 12)]
    technical_json = {"services": services}
    flags = _build_service_flags(technical_json)
    # ensures we don't return more than the cap (6)
    assert len(flags) <= 6
    # ensure entries contain port labels
    assert all(str("Port") in (f.split(":", 1)[0]) or "Port" in f for f in flags)
