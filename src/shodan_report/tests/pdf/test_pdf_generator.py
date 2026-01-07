from unittest.mock import MagicMock
from pathlib import Path

import pytest

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

    monkeypatch.setattr(pdf_generator, "OUTPUT_DIR", tmp_path / "reports")

    result_path = generate_pdf(customer, month, ip, mgmt, trend, technical)

    expected_dir = tmp_path / "reports" / customer.replace(" ", "_")
    expected_file = f"{month}_{ip}.pdf"
    expected_path = expected_dir / expected_file

    assert isinstance(result_path, Path)
    assert result_path == expected_path

    prepare_mock.assert_called_once_with(customer, month, ip, mgmt, trend, technical)

    render_mock.assert_called_once_with(expected_path, elements)


def test_generate_pdf_sanitizes_ip_in_filename(tmp_path, monkeypatch):
    customer = "Test"
    month = "2026-01"
    ip = "fe80::1"  #  : sollte ersetzt werden

    monkeypatch.setattr(pdf_generator, "prepare_pdf_elements", MagicMock(return_value=[]))
    monkeypatch.setattr(pdf_generator, "render_pdf", MagicMock())
    monkeypatch.setattr(pdf_generator, "OUTPUT_DIR", tmp_path / "reports")

    result_path = generate_pdf(customer, month, ip, "m", "t", {})
    assert ":" not in result_path.name
    assert "/" not in result_path.name
