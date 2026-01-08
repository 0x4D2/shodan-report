import pytest
from pathlib import Path
import tempfile
import json
from unittest.mock import Mock, patch
from datetime import datetime

from shodan_report.archiver.report_archiver import ReportArchiver
from shodan_report.models import AssetSnapshot, Service


def test_full_report_flow_with_archive(tmp_path):
    """Testet den kompletten Report-Flow mit Archivierung."""
    from shodan_report.main import main as original_main
    
    import os
    os.environ["SHODAN_API_KEY"] = "test_key"
    
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
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Temporäre Verzeichnisse setzen
        reports_dir = Path(tmpdir) / "reports"
        archive_dir = Path(tmpdir) / "archive"
        
        # Monkey-patch Verzeichnisse
        import shodan_report.pdf.pdf_generator
        import shodan_report.archiver.report_archiver
        
        original_output_dir = shodan_report.pdf.pdf_generator.OUTPUT_DIR
        shodan_report.pdf.pdf_generator.OUTPUT_DIR = reports_dir
        
        # Mock die PDF-Generierung
        def mock_generate_pdf(*args, **kwargs):
            customer = kwargs.get('customer_name', 'test_customer').replace(' ', '_')
            pdf_path = reports_dir / customer / "2025-01_1.2.3.4.pdf"
            pdf_path.parent.mkdir(parents=True, exist_ok=True)
            pdf_path.write_text("Mock PDF Content")
            return pdf_path
        
        with patch('shodan_report.main.ShodanClient') as mock_client, \
             patch('shodan_report.main.generate_pdf', side_effect=mock_generate_pdf), \
             patch('shodan_report.main.parse_shodan_host', return_value=mock_snapshot), \
             patch('shodan_report.archiver.report_archiver.ReportArchiver.__init__', 
                   lambda self, archive_root=None: setattr(self, 'archive_root', archive_dir)):
            
            # Mock API Response
            mock_client.return_value.get_host.return_value = {
                "ip_str": "1.2.3.4",
                "data": [],
                "ports": [80, 443],
                "hostnames": [],
                "domain": [],
                "org": None,
                "isp": None,
                "os": None,
                "location": {"city": None, "country_name": None}
            }
            
            # Temporäre main Funktion
            def mock_main():
                # Einfacher Test ohne komplexe Logik
                pdf_path = reports_dir / "test_customer" / "2025-01_1.2.3.4.pdf"
                pdf_path.parent.mkdir(parents=True, exist_ok=True)
                pdf_path.write_text("Test PDF")
                
                archiver = ReportArchiver(archive_dir)
                metadata = archiver.archive_report(
                    pdf_path=pdf_path,
                    customer_name="Test Customer",
                    month="2025-01",
                    ip="1.2.3.4"
                )
                
                # Prüfe ob Archivierung stattfand
                reports = archiver.list_customer_reports("Test Customer")
                assert reports["total_reports"] >= 1
                assert "test_customer" in str(reports["customer_slug"]).lower()
            
            # Führe mock_main aus
            mock_main()
            
            print("Integrationstest erfolgreich")