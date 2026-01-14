from typing import Any

from shodan_report.pdf.pdf_manager import prepare_pdf_elements


def mock_section_one(**kwargs: Any):
    elements = kwargs.get("elements")
    elements.append("MOCK_SECTION_ONE")


def mock_section_two(**kwargs: Any):
    elements = kwargs.get("elements")
    elements.append("MOCK_SECTION_TWO")


def test_prepare_pdf_elements_with_mock_sections():
    technical_json = {"open_ports": []}
    evaluation = {"risk": "low"}

    elements = prepare_pdf_elements(
        customer_name="ACME",
        month="2026-01",
        ip="1.2.3.4",
        management_text="Test",
        trend_text="Trend",
        technical_json=technical_json,
        evaluation=evaluation,
        business_risk="LOW",
        config={},
        sections=[mock_section_one, mock_section_two],
    )

    assert elements[0] == "MOCK_SECTION_ONE"
    assert elements[1] == "MOCK_SECTION_TWO"
