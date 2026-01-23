from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock

from shodan_report.models import AssetSnapshot, Service
from shodan_report.evaluation.evaluation import evaluate_snapshot
from shodan_report.evaluation.risk_prioritization import prioritize_risk
from shodan_report.reporting.management_text import generate_management_text
from shodan_report.pdf.pdf_generator import generate_pdf
from shodan_report.pdf import pdf_generator
from shodan_report.reporting.technical_data import build_technical_data


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
    prev = _make_snapshot(
        "1.2.3.4",
        ports=[22],
        services=[Service(port=22, transport="tcp", product="ssh", version="8.1")],
    )
    curr = _make_snapshot(
        "1.2.3.4",
        ports=[22, 443],
        services=[
            Service(port=22, transport="tcp", product="ssh", version="8.1"),
            Service(port=443, transport="tcp", product="https", version="1.0"),
        ],
    )

    evaluation = evaluate_snapshot(curr)
    business_risk = prioritize_risk(evaluation)
    mgmt_text = generate_management_text(business_risk, evaluation)

    technical_json = build_technical_data(curr, prev)

    monkeypatch.setattr(pdf_generator, "OUTPUT_DIR", tmp_path / "reports")

    def fake_render(path: Path, elements):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(mgmt_text)

    monkeypatch.setattr(pdf_generator, "render_pdf", fake_render)

    result_path = generate_pdf(
        customer_name="IntegrationCustomer",
        month="2026-01",
        ip=curr.ip,
        management_text=mgmt_text,
        trend_text="",  #
        technical_json=technical_json,
        evaluation=evaluation,
        business_risk=(
            business_risk.value
            if hasattr(business_risk, "value")
            else str(business_risk)
        ),
        output_dir=tmp_path / "reports",
    )

    assert result_path.exists()
    content = result_path.read_text(encoding="utf-8")
    assert mgmt_text in content


def test_pdf_and_archive_integration(tmp_path, monkeypatch):

    # Setup
    monkeypatch.setattr(pdf_generator, "OUTPUT_DIR", tmp_path / "reports")
    monkeypatch.setattr("shodan_report.archiver.core.ARCHIVE_DIR", tmp_path / "archive")

    curr = _make_snapshot(
        "1.2.3.4",
        ports=[22, 443],
        services=[
            Service(port=22, transport="tcp", product="ssh", version="8.1"),
            Service(port=443, transport="tcp", product="https", version="1.0"),
        ],
    )

    evaluation = evaluate_snapshot(curr)
    business_risk = prioritize_risk(evaluation)
    mgmt_text = generate_management_text(business_risk, evaluation)

    technical_json = build_technical_data(curr, None)

    # Mock für render_pdf
    def fake_render(path: Path, elements):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("PDF Content", encoding="utf-8")

    monkeypatch.setattr(pdf_generator, "render_pdf", fake_render)

    # Importiere die Archiv-Funktion
    from shodan_report.archiver.core import archive_snapshot

    customer_name = "IntegrationCustomer"
    month = "2026-01"

    # 1. Archivieren (unabhängig von PDF)
    archive_path = archive_snapshot(curr, customer_name, month)

    pdf_path = generate_pdf(
        customer_name=customer_name,
        month=month,
        ip=curr.ip,
        management_text=mgmt_text,
        trend_text="",
        technical_json=technical_json,
        evaluation=evaluation,
        business_risk=(
            business_risk.value
            if hasattr(business_risk, "value")
            else str(business_risk)
        ),
        output_dir=tmp_path / "reports",
    )

    assert archive_path.exists()
    assert pdf_path.exists()

    import json

    archive_data = json.loads(archive_path.read_text())
    assert archive_data["ip"] == curr.ip
    assert len(archive_data["services"]) == 2

    assert pdf_path.parent.name == customer_name.replace(" ", "_")
    assert pdf_path.name == f"{month}_{curr.ip}.pdf"


def test_main_flow_simulation(tmp_path, monkeypatch):
    # Setup temporäre Verzeichnisse
    monkeypatch.setattr(pdf_generator, "OUTPUT_DIR", tmp_path / "reports")
    monkeypatch.setattr("shodan_report.archiver.core.ARCHIVE_DIR", tmp_path / "archive")

    # Mock für ShodanClient (vereinfacht)
    class MockShodanClient:
        def get_host(self, ip):
            return {
                "ip_str": ip,
                "data": [
                    {
                        "port": 22,
                        "transport": "tcp",
                        "product": "ssh",
                        "version": "8.1",
                    },
                    {
                        "port": 443,
                        "transport": "tcp",
                        "product": "https",
                        "version": "1.0",
                    },
                ],
                "hostnames": [],
                "domain": [],
                "org": "Test Org",
                "isp": "Test ISP",
                "os": "Linux",
                "location": {"city": "Test City", "country_name": "Test Country"},
                "ports": [22, 443],
            }

    def fake_render(path: Path, elements):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"PDF for {path.name}", encoding="utf-8")

    monkeypatch.setattr(pdf_generator, "render_pdf", fake_render)

    from shodan_report.parsing.utils import parse_shodan_host
    from shodan_report.archiver.core import archive_snapshot
    from shodan_report.persistence.snapshot_manager import save_snapshot
    from shodan_report.reporting.technical_data import build_technical_data

    ip = "1.2.3.4"
    customer_name = "TestCustomer"
    month = "2026-01"

    client = MockShodanClient()
    raw_data = client.get_host(ip)
    snapshot = parse_shodan_host(raw_data)

    save_snapshot(snapshot, customer_name, month)

    archive_path = archive_snapshot(snapshot, customer_name, month)

    evaluation = evaluate_snapshot(snapshot)
    business_risk = prioritize_risk(evaluation)
    mgmt_text = generate_management_text(business_risk, evaluation)

    technical_json = build_technical_data(snapshot, None)

    pdf_path = generate_pdf(
        customer_name=customer_name,
        month=month,
        ip=ip,
        management_text=mgmt_text,
        trend_text="",  # Leerer Trend
        technical_json=technical_json,
        evaluation=evaluation,
        business_risk=(
            business_risk.value
            if hasattr(business_risk, "value")
            else str(business_risk)
        ),
        output_dir=tmp_path / "reports",
    )

    assert archive_path.exists()
    assert pdf_path.exists()
    print(f"Archiv: {archive_path}")
    print(f"PDF: {pdf_path}")
