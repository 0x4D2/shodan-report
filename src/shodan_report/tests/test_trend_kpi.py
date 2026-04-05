import pytest
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from shodan_report.pdf.styles import create_styles, DEFAULT_THEME
from shodan_report.pdf.sections import trend

@pytest.fixture
def styles():
    return create_styles(DEFAULT_THEME)

@pytest.fixture
def elements():
    return []

def test_kpi_cards_rendering(elements, styles):
    # Minimal trend_table for KPI
    trend_table = {
        "Öffentliche Ports": (3, 2, "verbessert"),
        "Hochrisiko-CVEs": (1, 2, "verschlechtert"),
    }
    tbl = trend._build_kpi_cards(styles, "Mär 2026", trend_table, 3, 2)
    assert tbl._ncols == 5
    assert tbl._nrows == 1
    # Check that the table width fits the page (<= 183mm)
    total_width = sum(tbl._colWidths)
    assert total_width <= 183 * 2.83465  # mm to points

def test_trend_section_runs(elements, styles):
    # Should not raise
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
    assert any(isinstance(e, Spacer) for e in elements)
    # Paragraphs können in KeepTogether/Table verschachtelt sein
    def find_paragraphs(elist):
        from reportlab.platypus import Paragraph, Table, KeepTogether
        found = []
        for e in elist:
            if isinstance(e, Paragraph):
                found.append(e)
            elif isinstance(e, (Table, KeepTogether)):
                # Table: check _cellvalues, KeepTogether: _content
                for attr in ("_cellvalues", "_content"):
                    inner = getattr(e, attr, None)
                    if inner:
                        found.extend(find_paragraphs(inner))
        return found
    assert find_paragraphs(elements), "No Paragraphs found in elements or children"
