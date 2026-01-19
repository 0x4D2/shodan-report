import json
import pytest
from pathlib import Path
from reportlab.platypus import Table

from shodan_report.pdf.pdf_generator import generate_pdf


def _make_sparse_snapshot():
    return {
        "open_ports": [],
        "vulnerabilities": [],
        "tls_weaknesses": [],
        "services": [],
    }


def _make_dense_snapshot(service_count=50, cves_per_service=3):
    services = []
    for i in range(service_count):
        sv = {
            "port": 1000 + i,
            "product": f"ServiceProduct{i}",
            "version": "1.0.0",
            "banner": "X" * (200 if i % 5 == 0 else 40),
            "vulnerabilities": [{"id": f"CVE-2026-000{i}-{j}", "cvss": 7.5 + (j % 3)} for j in range(cves_per_service)],
            "ssl_info": {"has_weak_cipher": (i % 7 == 0)},
        }
        services.append(sv)

    top_level_cves = [{"id": f"CVE-2026-TOP-{i}", "cvss": 9.0} for i in range(5)]

    return {
        "open_ports": services,
        "services": services,
        "vulnerabilities": top_level_cves,
        "tls_weaknesses": ["weak-cipher" for _ in range(3)],
    }


def test_generate_demo_pdfs(monkeypatch, tmp_path):
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

    out_dir = tmp_path / "reports"

    # Sparse PDF
    sparse = _make_sparse_snapshot()
    sparse_pdf = generate_pdf(
        customer_name="DEMO_SPARSE",
        month="2026-01",
        ip="1.2.3.4",
        management_text=("Kurzer Text."),
        trend_text=("Keine besonderen Änderungen."),
        technical_json=sparse,
        evaluation={},
        business_risk="low",
        output_dir=out_dir,
    )

    assert sparse_pdf.exists(), "Sparse PDF should be generated"
    sparse_size = sparse_pdf.stat().st_size
    assert sparse_size > 0

    # Dense PDF
    dense = _make_dense_snapshot(service_count=80, cves_per_service=5)
    long_management = "\n".join(["Detaillierte Zeile: " + ("X" * 200) for _ in range(40)])
    long_trend = "\n".join(["• Punkt mit vielen Details " + ("Y" * 150) for _ in range(30)])

    dense_pdf = generate_pdf(
        customer_name="DEMO_DENSE",
        month="2026-01",
        ip="203.0.113.5",
        management_text=long_management,
        trend_text=long_trend,
        technical_json=dense,
        evaluation={"cves": []},
        business_risk="high",
        output_dir=out_dir,
    )

    assert dense_pdf.exists(), "Dense PDF should be generated"
    dense_size = dense_pdf.stat().st_size
    assert dense_size > 0

    # Dense PDF should be larger than sparse
    assert dense_size > sparse_size, "Dense PDF should be larger than Sparse PDF"

    # Optionally assert that at least one Table was created in the PDF elements by calling prepare_pdf_elements
    from shodan_report.pdf.pdf_manager import prepare_pdf_elements

    dense_elements = prepare_pdf_elements(
        "DEMO_DENSE",
        "2026-01",
        "203.0.113.5",
        long_management,
        long_trend,
        dense,
        {"cves": []},
        "high",
        config={},
    )

    assert any(isinstance(e, Table) for e in dense_elements), "At least one Table should be in PDF flowables"
