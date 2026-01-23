import pytest
from pathlib import Path
from shodan_report.pdf.pdf_generator import generate_pdf


def _sparse_snapshot():
    return {"open_ports": [], "vulnerabilities": [], "services": []}


def _dense_snapshot(n_services=120, cves_each=4):
    services = []
    for i in range(n_services):
        services.append(
            {
                "port": 1000 + i,
                "product": f"Srv{i}",
                "version": "0.1",
                "banner": "B" * (500 if i % 11 == 0 else 80),
                "vulnerabilities": [{"id": f"CVE-2026-{i:04d}-{j}", "cvss": 7.5 + (j % 3)} for j in range(cves_each)],
                "ssl_info": {"has_weak_cipher": i % 13 == 0},
            }
        )
    top = [{"id": f"CVE-2026-TOP-{i}", "cvss": 9.0} for i in range(10)]
    return {"open_ports": services, "services": services, "vulnerabilities": top, "tls_weaknesses": ["weak" for _ in range(5)]}


def _multilingual_snapshot():
    return {
        "open_ports": [
            {"port": 443, "product": "nginx", "version": "1.22.0", "banner": "Grüße 🌍 – Sonderzeichen: äöüß"}
        ],
        "vulnerabilities": [],
        "services": [],
    }


def _many_short_lines_text(lines=200):
    return "\n".join([f"Kurzzeile {i}" for i in range(lines)])


def test_generate_many_demo_variants(monkeypatch, tmp_path):
    # Inject dummy NVD and CISA clients to avoid network calls during PDF generation
    class DummyNvdClient:
        def fetch_cve_json(self, cve_id):
            return {}

    class DummyCisaClient:
        def fetch_kev_set(self):
            return set()

    monkeypatch.setattr(
        'shodan_report.pdf.sections.data.cve_enricher.NvdClient',
        lambda *a, **kw: DummyNvdClient(),
    )
    monkeypatch.setattr(
        'shodan_report.pdf.sections.data.cve_enricher.CisaClient',
        lambda *a, **kw: DummyCisaClient(),
    )
    out = Path("reports") / "demo"
    out.mkdir(parents=True, exist_ok=True)

    variants = []

    # sparse
    variants.append(("demo_sparse", "2026-01", "1.2.3.4", "Kurz", "Keine Änderungen.", _sparse_snapshot(), {}))

    # dense
    dense = _dense_snapshot()
    long_text = "\n".join(["Detail: " + ("X" * 300) for _ in range(60)])
    variants.append(("demo_dense", "2026-01", "203.0.113.5", long_text, "Viele Änderungen", dense, {"cves": []}))

    # multilingual
    variants.append(("demo_multi", "2026-01", "198.51.100.7", "Mehrsprachig: Grüße", "Änderungen: 🌐🚀", _multilingual_snapshot(), {}))

    # many short lines
    short_text = _many_short_lines_text(300)
    variants.append(("demo_shortlines", "2026-01", "192.0.2.8", short_text, short_text, _sparse_snapshot(), {}))

    # extreme banners
    extreme = _dense_snapshot(n_services=30, cves_each=1)
    for i in range(len(extreme["open_ports"])):
        extreme["open_ports"][i]["banner"] = "A" * (2000 if i % 7 == 0 else 120)
    variants.append(("demo_extreme_banners", "2026-01", "203.0.113.9", "Banner Test", "Banner Trend", extreme, {}))

    generated = []
    for name, month, ip, mtext, ttext, tech, evalobj in variants:
        pdf_path = generate_pdf(
            customer_name=name,
            month=month,
            ip=ip,
            management_text=mtext,
            trend_text=ttext,
            technical_json=tech,
            evaluation=evalobj,
            business_risk="medium",
            output_dir=out,
        )
        assert pdf_path.exists(), f"{name} PDF should exist"
        assert pdf_path.stat().st_size > 0, f"{name} PDF should not be empty"
        generated.append(pdf_path)

    # sanity: at least two PDFs should differ in size
    sizes = [p.stat().st_size for p in generated]
    assert len(set(sizes)) > 1, "Generated PDFs should vary in size"
