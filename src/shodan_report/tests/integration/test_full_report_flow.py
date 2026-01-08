from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock

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
    """Testet NUR die PDF-Generierung, nicht die Archivierung"""
    prev = _make_snapshot("1.2.3.4", ports=[22], services=[
        Service(port=22, transport="tcp", product="ssh", version="8.1")
    ])
    curr = _make_snapshot("1.2.3.4", ports=[22, 443], services=[
        Service(port=22, transport="tcp", product="ssh", version="8.1"),
        Service(port=443, transport="tcp", product="https", version="1.0")
    ])

    evaluation = evaluate_snapshot(curr)
    business_risk = prioritize_risk(evaluation)
    mgmt_text = generate_management_text(business_risk, evaluation)

    monkeypatch.setattr(pdf_generator, "OUTPUT_DIR", tmp_path / "reports")

    def fake_render(path: Path, elements):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(mgmt_text)

    monkeypatch.setattr(pdf_generator, "render_pdf", fake_render)

    # KEIN Mock für archive_snapshot nötig, da nicht in generate_pdf aufgerufen
    result_path = generate_pdf("IntegrationCustomer", "2026-01", curr.ip, mgmt_text, "", {})

    assert result_path.exists()
    content = result_path.read_text(encoding="utf-8")
    assert mgmt_text in content
    # KEINE Prüfung auf archive_snapshot, da nicht Teil dieser Funktion


def test_pdf_and_archive_integration(tmp_path, monkeypatch):
    """Testet die Integration von PDF-Generierung UND Archivierung"""
    # Setup
    monkeypatch.setattr(pdf_generator, "OUTPUT_DIR", tmp_path / "reports")
    monkeypatch.setattr("shodan_report.archiver.core.ARCHIVE_DIR", tmp_path / "archive")
    
    curr = _make_snapshot("1.2.3.4", ports=[22, 443], services=[
        Service(port=22, transport="tcp", product="ssh", version="8.1"),
        Service(port=443, transport="tcp", product="https", version="1.0")
    ])
    
    evaluation = evaluate_snapshot(curr)
    business_risk = prioritize_risk(evaluation)
    mgmt_text = generate_management_text(business_risk, evaluation)

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
    
    # 2. PDF generieren (unabhängig von Archiv)
    pdf_path = generate_pdf(customer_name, month, curr.ip, mgmt_text, "", {})
    
    # Assertions für BEIDE Funktionen
    assert archive_path.exists()
    assert pdf_path.exists()
    
    # Prüfe Archiv-Daten
    import json
    archive_data = json.loads(archive_path.read_text())
    assert archive_data["ip"] == curr.ip
    assert len(archive_data["services"]) == 2
    
    # Prüfe PDF-Verzeichnis-Struktur
    assert pdf_path.parent.name == customer_name.replace(" ", "_")
    assert pdf_path.name == f"{month}_{curr.ip}.pdf"


def test_main_flow_simulation(tmp_path, monkeypatch):
    """Simuliert den kompletten main()-Flow wie in main.py"""
    # Setup temporäre Verzeichnisse
    monkeypatch.setattr(pdf_generator, "OUTPUT_DIR", tmp_path / "reports")
    monkeypatch.setattr("shodan_report.archiver.core.ARCHIVE_DIR", tmp_path / "archive")
    
    # Mock für ShodanClient (vereinfacht)
    class MockShodanClient:
        def get_host(self, ip):
            return {
                "ip_str": ip,
                "data": [
                    {"port": 22, "transport": "tcp", "product": "ssh", "version": "8.1"},
                    {"port": 443, "transport": "tcp", "product": "https", "version": "1.0"}
                ],
                "hostnames": [],
                "domain": [],
                "org": "Test Org",
                "isp": "Test ISP",
                "os": "Linux",
                "location": {"city": "Test City", "country_name": "Test Country"},
                "ports": [22, 443]
            }
    
    # Mock render_pdf
    def fake_render(path: Path, elements):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"PDF for {path.name}", encoding="utf-8")
    
    monkeypatch.setattr(pdf_generator, "render_pdf", fake_render)
    
    # Importiere alle benötigten Funktionen
    from shodan_report.parsing.utils import parse_shodan_host
    from shodan_report.archiver.core import archive_snapshot
    from shodan_report.persistence.snapshot_manager import save_snapshot
    from shodan_report.reporting.technical_data import build_technical_data
    
    # Simuliere main()-Flow
    ip = "1.2.3.4"
    customer_name = "TestCustomer"
    month = "2026-01"
    
    # 1. Shodan-Daten abrufen und parsen
    client = MockShodanClient()
    raw_data = client.get_host(ip)
    snapshot = parse_shodan_host(raw_data)
    
    # 2. Snapshot speichern (optional)
    save_snapshot(snapshot, customer_name, month)
    
    # 3. Archivieren
    archive_path = archive_snapshot(snapshot, customer_name, month)
    
    # 4. Bewerten
    evaluation = evaluate_snapshot(snapshot)
    business_risk = prioritize_risk(evaluation)
    mgmt_text = generate_management_text(business_risk, evaluation)
    
    # 5. Technische Daten
    technical_json = build_technical_data(snapshot, None)
    
    # 6. PDF generieren
    pdf_path = generate_pdf(customer_name, month, ip, mgmt_text, "", technical_json)
    
    # Validierung
    assert archive_path.exists()
    assert pdf_path.exists()
    print(f"Archiv: {archive_path}")
    print(f"PDF: {pdf_path}")