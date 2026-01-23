import pytest
from pathlib import Path
from shodan_report.evaluation.evaluation import Evaluation, RiskLevel  # ⭐ NEU


def test_pdf_generator_integration(tmp_path):
    from shodan_report.pdf.pdf_generator import generate_pdf

    mock_evaluation = Evaluation(
        ip="8.8.8.8", risk=RiskLevel.MEDIUM, critical_points=["Test kritischer Punkt"]
    )
    mock_business_risk = "medium"

    # Mock-Daten
    test_data = {
        "customer_name": "Integration Test",
        "month": "2025-01",
        "ip": "8.8.8.8",
        "management_text": "Test Management",
        "trend_text": "Stable trend",
        "technical_json": {
            "open_ports": [{"port": 80, "service": {"product": "Test Server"}}]
        },
        "evaluation": mock_evaluation,
        "business_risk": mock_business_risk,
        "output_dir": tmp_path,
        "config": {"styling": {"primary_color": "#0000FF"}},
    }

    # Generiere PDF
    pdf_path = generate_pdf(**test_data)

    assert pdf_path.exists()
    assert pdf_path.suffix == ".pdf"
    assert pdf_path.stat().st_size > 0  # PDF ist nicht leer
