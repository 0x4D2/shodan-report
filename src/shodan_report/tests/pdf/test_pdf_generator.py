# src/shodan_report/tests/pdf/test_pdf_generator.py
import pytest
from pathlib import Path
from unittest.mock import MagicMock
from shodan_report.pdf import pdf_generator
from shodan_report.pdf.pdf_generator import generate_pdf


def test_generate_pdf_calls_renderer_and_returns_path(tmp_path, monkeypatch):
    customer = "Acme Inc"
    month = "2026-01"
    ip = "1.2.3.4"
    mgmt = "management text"
    trend = "trend text"
    technical = {"open_ports": []}

    # Prepare mocks
    elements = [{"type": "header", "text": "Acme"}]
    prepare_mock = MagicMock(return_value=elements)
    render_mock = MagicMock()

    monkeypatch.setattr(pdf_generator, "prepare_pdf_elements", prepare_mock)
    monkeypatch.setattr(pdf_generator, "render_pdf", render_mock)

    # WICHTIG: output_dir explizit setzen
    result_path = generate_pdf(
        customer_name=customer,
        month=month,
        ip=ip,
        management_text=mgmt,
        trend_text=trend,
        technical_json=technical,
        output_dir=tmp_path / "reports"  # EXPLIZIT setzen
    )

    # Expected path berechnen
    expected_dir = tmp_path / "reports" / customer.replace(" ", "_")
    expected_file = f"{month}_{ip}.pdf"
    expected_path = expected_dir / expected_file

    # Assertions
    assert isinstance(result_path, Path)
    assert result_path == expected_path  # Sollte jetzt passen
    prepare_mock.assert_called_once_with(
        customer, month, ip, mgmt, trend, technical
    )
    render_mock.assert_called_once_with(expected_path, elements)