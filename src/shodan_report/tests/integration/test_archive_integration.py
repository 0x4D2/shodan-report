import pytest
import json
from unittest.mock import patch
from datetime import datetime

from shodan_report.archiver.report_archiver import ReportArchiver
from shodan_report.models import AssetSnapshot, Service


def test_full_report_flow_with_archive(tmp_path):
    """Testet den kompletten Report-Flow mit Archivierung (neue CLI Architektur)."""
    # Importiere die neuen Komponenten
    from shodan_report.core.runner import generate_report_pipeline
    
    # Setup temporäre Verzeichnisse
    reports_dir = tmp_path / "reports"
    archive_dir = tmp_path / "archive"
    
    reports_dir.mkdir()
    archive_dir.mkdir()
    
    # Mock AssetSnapshot erstellen
    mock_snapshot = AssetSnapshot(
        ip="1.2.3.4",
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=[
            Service(port=80, transport="tcp", product="HTTP"),
            Service(port=443, transport="tcp", product="HTTPS"),
        ],
        open_ports=[80, 443],
        last_update=datetime.now(),
        raw_banner=[],
        ssl_info=None,
        ssh_info=None
    )
    
    # Mock Management-Text und Trend
    mock_management_text = "Test Management Zusammenfassung für IP 1.2.3.4"
    mock_trend_text = "Stabile Entwicklung über die letzten 3 Monate"
    mock_technical_json = {
        "open_ports": [
            {"port": 80, "service": {"product": "HTTP"}},
            {"port": 443, "service": {"product": "HTTPS"}}
        ]
    }
    
    with patch('shodan_report.core.runner.ShodanClient') as mock_client, \
         patch('shodan_report.core.runner.parse_shodan_host', return_value=mock_snapshot), \
         patch('shodan_report.core.runner.generate_management_text', return_value=mock_management_text), \
         patch('shodan_report.core.runner.analyze_trend', return_value=mock_trend_text), \
         patch('shodan_report.core.runner.build_technical_data', return_value=mock_technical_json), \
         patch('shodan_report.pdf.pdf_generator.generate_pdf') as mock_generate_pdf:
        
        # Setup Mock PDF Generator - ERSTELLE ECHTE PDF
        mock_pdf_path = reports_dir / "Test_Customer" / "2025-01_1.2.3.4.pdf"
        mock_pdf_path.parent.mkdir(parents=True, exist_ok=True)
        # Schreibe echten PDF-Inhalt (minimal gültiges PDF)
        pdf_content = b'%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[]/Count 0>>\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000010 00000 n\n0000000053 00000 n\ntrailer\n<</Size 3/Root 1 0 R>>\nstartxref\n149\n%%EOF'
        mock_pdf_path.write_bytes(pdf_content)
        mock_generate_pdf.return_value = mock_pdf_path
        
        # Setup Mock Shodan API
        mock_client.return_value.get_host.return_value = {
            "ip_str": "1.2.3.4",
            "data": [],
            "ports": [80, 443],
            "hostnames": [],
            "domain": [],
            "org": "Test ISP",
            "isp": "Test ISP",
            "os": "Linux",
            "location": {"city": "Berlin", "country_name": "Germany"}
        }
        
        # Setup Mock Archivierung mit ECHTEM Archiver
        from shodan_report.archiver.report_archiver import ReportArchiver
        real_archiver = ReportArchiver(archive_root=archive_dir)
        
        with patch('shodan_report.core.runner.ReportArchiver', return_value=real_archiver):
            # Führe die Pipeline aus
            result = generate_report_pipeline(
                customer_name="Test Customer",
                ip="1.2.3.4",
                month="2025-01",
                compare_month=None,
                config_path=None,
                output_dir=reports_dir,
                archive=True,
                verbose=False
            )
            
            # DEBUG
            print(f"DEBUG Result: {result}")
            
            # Verifikation - prüfe ob PDF erstellt wurde
            assert result["success"] is True
            assert "pdf_path" in result
            assert result["pdf_path"].exists()
            
            # Archiv-Pfad ist ein RELATIVER String (relativ zum Archiv-Root)
            assert "archive_path" in result
            archive_path_str = result["archive_path"]
            
            # Kombiniere mit Archiv-Root für vollen Pfad
            full_archive_path = archive_dir / archive_path_str
            assert full_archive_path.exists()
            
            print("✅ Integrationstest erfolgreich: Vollständige Pipeline getestet")


def test_archive_integration_directly(tmp_path):
    # Setup
    archive_dir = tmp_path / "archive"
    reports_dir = tmp_path / "reports"
    
    reports_dir.mkdir()
    archive_dir.mkdir()
    
    # Erstelle eine Test-PDF mit minimalem gültigem PDF-Content
    test_pdf = reports_dir / "test_report.pdf"
    pdf_content = b'%PDF-1.4\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[]/Count 0>>\nendobj\nxref\n0 3\n0000000000 65535 f\n0000000010 00000 n\n0000000053 00000 n\ntrailer\n<</Size 3/Root 1 0 R>>\nstartxref\n149\n%%EOF'
    test_pdf.write_bytes(pdf_content)
    
    # Teste die Archivierung direkt
    archiver = ReportArchiver(archive_root=archive_dir)
    
    metadata = archiver.archive_report(
        pdf_path=test_pdf,
        customer_name="Integration Test Customer",
        month="2025-01",
        ip="8.8.8.8"
    )
    
    # WICHTIGSTE PRÜFUNG: archive_report gibt Metadaten zurück
    assert isinstance(metadata, dict)
    assert "sha256" in metadata
    assert "pdf_path" in metadata
    
    # Prüfe ob Dateien erstellt wurden
    relative_path = metadata["pdf_path"]
    full_archive_path = archive_dir / relative_path
    
    # 1. PDF existiert
    assert full_archive_path.exists(), f"PDF nicht archiviert: {full_archive_path}"
    
    # 2. Metadaten-Datei existiert (egal welches Format)
    json_files = list(full_archive_path.parent.glob('*.json'))
    assert len(json_files) > 0, "Keine Metadaten-Datei gefunden"
    
    # 3. Metadaten können geladen werden
    metadata_file = json_files[0]
    with open(metadata_file, 'r') as f:
        saved_data = json.load(f)
    
    assert isinstance(saved_data, dict)
    assert len(saved_data) > 0
    
    print(f" Archivierung erfolgreich:")
    print(f" PDF: {full_archive_path}")
    print(f" Metadaten: {metadata_file}")
    print(f" SHA256: {metadata.get('sha256', 'N/A')}")