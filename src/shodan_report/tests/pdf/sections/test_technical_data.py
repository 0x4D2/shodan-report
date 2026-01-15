from shodan_report.pdf.sections.data.technical_data import prepare_technical_detail


def test_prepare_technical_detail_basic():
    technical_json = {
        "open_ports": [
            {
                "port": 443,
                "service": "https",
                "product": "nginx",
                "version": "1.18.0",
                "ssl_info": {"protocols": ["TLSv1.2"], "has_weak_cipher": False, "cert": {"not_after": "2026-06-01"}},
                "vulnerabilities": [{"id": "CVE-2021-1234", "cvss": 5.6}],
            },
            {
                "port": 80,
                "service": "http",
                "product": "Apache",
                "version": "2.4.46",
                "vulnerabilities": [{"id": "CVE-2020-9999", "cvss": 7.5}],
            },
        ],
        "hostnames": ["example.com"],
        "vulnerabilities": [],
    }

    out = prepare_technical_detail(technical_json, evaluation=None)
    assert isinstance(out, dict)
    assert "services" in out
    sv = out["services"]
    assert len(sv) == 2
    # https first: cert expiry and low CVE
    https = next((x for x in sv if x["port"] == 443), None)
    assert https is not None
    assert https["tls"]["cert_expiry"] == "2026-06-01"
    # http has a high CVSS -> risk hoch
    http = next((x for x in sv if x["port"] == 80), None)
    assert http is not None
    assert http["high_cvss"] == 1
    assert http["risk"] == "hoch"
