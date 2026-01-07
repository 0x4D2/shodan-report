from pathlib import Path
from datetime import datetime

from shodan_report.models import AssetSnapshot, Service
from shodan_report.evaluation.evaluation import evaluate_snapshot
from shodan_report.evaluation.risk_prioritization import prioritize_risk
from shodan_report.reporting.management_text import generate_management_text
from shodan_report.pdf.pdf_generator import generate_pdf
from shodan_report.pdf import pdf_generator


def _make_snapshot(ip: str, ports=None, services=None):
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
        last_update=datetime.now(),
    )


def test_end_to_end_report_generation(tmp_path, monkeypatch):
    prev = _make_snapshot("1.2.3.4", ports=[22], services=[Service(port=22, transport="tcp", product="ssh", version="8.1")])
    curr = _make_snapshot("1.2.3.4", ports=[22, 443], services=[Service(port=22, transport="tcp", product="ssh", version="8.1"), Service(port=443, transport="tcp", product="https", version="1.0")])

    evaluation = evaluate_snapshot(curr)
    business_risk = prioritize_risk(evaluation)
    mgmt_text = generate_management_text(business_risk, evaluation)

    monkeypatch.setattr(pdf_generator, "OUTPUT_DIR", tmp_path / "reports")

    def fake_render(path: Path, elements):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(mgmt_text)

    monkeypatch.setattr(pdf_generator, "render_pdf", fake_render)

    result_path = generate_pdf("IntegrationCustomer", "2026-01", curr.ip, mgmt_text, "", {})

    assert result_path.exists()
    content = result_path.read_text(encoding="utf-8")
    assert mgmt_text in content
