import pytest
from reportlab.platypus import Paragraph, Spacer, KeepTogether, Table
from shodan_report.pdf.styles import create_styles, DEFAULT_THEME
from shodan_report.pdf.sections import trend

@pytest.fixture
def styles():
    return create_styles(DEFAULT_THEME)

@pytest.fixture
def elements():
    return []

def test_trend_section_runs_debug(elements, styles):
    trend.create_trend_section(
        elements, styles,
        trend_text="Testtrend", compare_month="Mär 2026",
        trend_table={
            "Öffentliche Ports": (3, 2, "verbessert"),
            "Hochrisiko-CVEs": (1, 2, "verschlechtert"),
        },
        technical_json={"previous_exposure_score": 3},
        evaluation={"exposure_score": 2},
    )
    print([type(e) for e in elements])
    for e in elements:
        if isinstance(e, (KeepTogether, Table)):
            print("Inner:", [type(x) for x in getattr(e, '._cellvalues', getattr(e, '._content', []))])
