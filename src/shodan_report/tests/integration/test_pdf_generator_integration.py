import pytest
from pathlib import Path

def test_pdf_generator_integration():
    """Integrationstest mit echtem PDF-Generator."""
    from shodan_report.pdf.pdf_generator import generate_pdf
    
    # Mock-Daten
    test_data = {
        "customer_name": "Integration Test",
        "month": "2025-01",
        "ip": "8.8.8.8",
        "management_text": "Test Management",
        "trend_text": "Stable trend",
        "technical_json": {
            "open_ports": [
                {"port": 80, "service": {"product": "Test Server"}}
            ]
        }
    }
    
    # Generiere PDF
    pdf_path = generate_pdf(
        **test_data,
        output_dir=Path("/tmp"),
        config={"styling": {"primary_color": "#0000FF"}}
    )
    
    assert pdf_path.exists()
    assert pdf_path.suffix == '.pdf'
    assert pdf_path.stat().st_size > 1000  # Mindestgröße