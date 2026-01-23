import json
from pathlib import Path

from shodan_report.pdf.pdf_generator import generate_pdf


def test_generate_pdf_writes_mdata_with_enrichment(tmp_path):
    technical_json = {
        "open_ports": [{"port": 22, "vulnerabilities": ["CVE-2025-0001"]}],
        "vulns": ["CVE-2025-0001"],
    }
    evaluation = {"exposure_score": 2, "risk": "medium", "cves": ["CVE-2025-0001"]}

    pdf_path = generate_pdf(
        customer_name="TEST",
        month="2026-01",
        ip="1.2.3.4",
        management_text="Mgmt",
        trend_text="Trend",
        technical_json=technical_json,
        evaluation=evaluation,
        business_risk="medium",
        output_dir=tmp_path,
    )

    mdata_file = pdf_path.parent / (pdf_path.stem + ".mdata.json")
    assert mdata_file.exists()
    data = json.loads(mdata_file.read_text(encoding="utf-8"))
    assert "cve_enriched_sample" in data
    assert isinstance(data["cve_enriched_sample"], list)
    assert data["cve_enriched_sample"][0]["id"] == "CVE-2025-0001"
