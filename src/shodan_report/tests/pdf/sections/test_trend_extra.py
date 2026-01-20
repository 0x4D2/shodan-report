import pytest
from datetime import datetime
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Table, Paragraph

from shodan_report.pdf.sections import trend as trend_mod
from shodan_report.reporting.technical_data import build_technical_data
from shodan_report.models import AssetSnapshot, Service


@pytest.fixture
def styles():
    base = getSampleStyleSheet()
    return {
        "heading2": base["Heading2"],
        "heading1": base["Heading1"],
        "normal": base["Normal"],
        "bullet": base["Normal"],
    }


def test_compute_rating_edge_cases():
    # equal
    assert trend_mod._compute_rating("Öffentliche Ports", 2, 2) == "unverändert"
    assert trend_mod._compute_rating("Kritische Services", 1, 1) == "stabil"

    # new when prev 0 and diff ==1
    assert trend_mod._compute_rating("Öffentliche Ports", 0, 1) == "neu"
    assert trend_mod._compute_rating("Kritische Services", 0, 2) == "verschlechtert"

    # small diffs
    assert trend_mod._compute_rating("Kritische Services", 2, 3) == "leicht verschlechtert"
    assert trend_mod._compute_rating("Kritische Services", 3, 2) == "leicht verbessert"


def test_derive_trend_table_basic():
    tech = {
        "open_ports": [{"port": 80}, {"port": 443}, {"port": 22}],
        "critical_services": ["https"],
        "vulnerabilities": [{"id": "CVE-1", "cvss": 9.0}],
        "previous_metrics": {
            "Öffentliche Ports": 2,
            "Kritische Services": 1,
            "Hochrisiko-CVEs": 0,
            "TLS-Schwächen": 0,
        },
    }
    evaluation = {"cves": [{"id": "CVE-2", "cvss": 7.5}], "previous_metrics": {}}

    tt = trend_mod._derive_trend_table(tech, evaluation)

    # keys present
    assert "Öffentliche Ports" in tt
    assert tt["Öffentliche Ports"][0] == 2
    assert tt["Öffentliche Ports"][1] == 3

    # high-risk CVEs should count both top-level and evaluation
    assert tt["Hochrisiko-CVEs"][1] >= 1


def test_derive_trend_table_ratings_are_consistent():
    tech = {
        "open_ports": [{"port": 80}, {"port": 443}, {"port": 22}],
        "critical_services": ["https", "ssh"],
        "vulnerabilities": [{"id": "CVE-1", "cvss": 9.8}],
        "previous_metrics": {
            "Öffentliche Ports": 3,
            "Kritische Services": 1,
            "Hochrisiko-CVEs": 0,
            "TLS-Schwächen": 2,
        },
    }

    tt = trend_mod._derive_trend_table(tech, evaluation=None)

    assert tt["Öffentliche Ports"] == (3, 3, "unverändert")
    assert tt["Kritische Services"] == (1, 2, "leicht verschlechtert")
    assert tt["Hochrisiko-CVEs"] == (0, 1, "neu")
    assert tt["TLS-Schwächen"][2] in {"leicht verbessert", "verbessert"}


def test_create_trend_section_table_rendering(styles):
    elements = []
    # supply an explicit trend_table to force table rendering
    trend_table = {
        "Öffentliche Ports": (5, 5, "unverändert"),
        "Kritische Services": (1, 1, "stabil"),
    }

    trend_mod.create_trend_section(
        elements=elements,
        styles=styles,
        trend_text="",
        compare_month="Dezember 2025",
        trend_table=trend_table,
    )

    # Expect a Table object and that it contains header cells matching the columns
    has_table = next((e for e in elements if isinstance(e, Table)), None)
    assert has_table is not None, "Table should be rendered when trend_table is provided"

    # inspect table data for header labels (cells are Paragraphs)
    data = getattr(has_table, '_cellvalues', None) or getattr(has_table, 'getPlainData', lambda: None)()
    # flatten header texts
    header = data[0]
    header_texts = [getattr(h, 'text', str(h)) for h in header]
    assert any('Kategorie' in t for t in header_texts), 'Header should include Kategorie'
    assert any('Vormonat' in t for t in header_texts), 'Header should include Vormonat'
    assert any('Aktuell' in t for t in header_texts), 'Header should include Aktuell'


def test_create_trend_section_derives_table_from_technical_json(styles):
    elements = []
    technical_json = {
        "open_ports": [{"port": 443, "product": "HTTP", "is_ssl": False, "ssl_info": None}],
        "previous_metrics": {
            "Öffentliche Ports": 1,
            "Kritische Services": 0,
            "Hochrisiko-CVEs": 0,
            "TLS-Schwächen": 1,
        },
    }

    trend_mod.create_trend_section(
        elements=elements,
        styles=styles,
        trend_text="",
        compare_month="Dezember 2025",
        technical_json=technical_json,
        evaluation=None,
    )

    has_table = next((e for e in elements if isinstance(e, Table)), None)
    assert has_table is not None, "Table should be rendered from derived trend table"

    data = getattr(has_table, '_cellvalues', None) or getattr(has_table, 'getPlainData', lambda: None)()

    def _cell_text(cell):
        if isinstance(cell, (list, tuple)) and cell:
            cell = cell[0]
        return getattr(cell, "text", str(cell))

    tls_row = None
    for row in data[1:]:
        if "TLS" in _cell_text(row[0]):
            tls_row = [_cell_text(c) for c in row]
            break

    assert tls_row is not None, "TLS-Schwächen row should be present"
    assert "1" in tls_row[1]
    assert "1" in tls_row[2]
    assert "stabil" in tls_row[3]


def test_trend_section_includes_interpretation_text(styles):
    elements = []
    trend_table = {
        "Öffentliche Ports": (3, 3, "unverändert"),
        "Kritische Services": (1, 1, "stabil"),
    }

    trend_mod.create_trend_section(
        elements=elements,
        styles=styles,
        trend_text="",
        compare_month="Dezember 2025",
        trend_table=trend_table,
    )

    texts = [getattr(e, "text", "") for e in elements if isinstance(e, Paragraph)]
    assert any("Interpretation:" in t for t in texts)
    assert any("Die Angriffsfläche ist stabil." in t for t in texts)


def test_tls_weaknesses_missing_ssl_info_counted():
    tech = {
        "open_ports": [
            {"port": 443, "product": "HTTP", "is_ssl": False, "ssl_info": None},
            {"port": 8443, "product": "HTTP", "is_ssl": False},
        ]
    }

    tt = trend_mod._derive_trend_table(tech, evaluation=None)

    assert tt["TLS-Schwächen"][1] == 2


def test_trend_table_identical_snapshots_tls_stable():
    prev = AssetSnapshot(
        ip="217.154.224.104",
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=[
            Service(port=22, transport="tcp", product="OpenSSH", version="8.9"),
            Service(port=80, transport="tcp", product="HTTP", version="1.1"),
            Service(port=443, transport="tcp", product="HTTP", version="1.1"),
        ],
        open_ports=[22, 80, 443],
        last_update=datetime(2025, 12, 15, 10, 0, 0),
    )

    curr = AssetSnapshot(
        ip="217.154.224.104",
        hostnames=[],
        domains=[],
        org=None,
        isp=None,
        os=None,
        city=None,
        country=None,
        services=[
            Service(port=22, transport="tcp", product="OpenSSH", version="8.9"),
            Service(port=80, transport="tcp", product="HTTP", version="1.1"),
            Service(port=443, transport="tcp", product="HTTP", version="1.1"),
        ],
        open_ports=[22, 80, 443],
        last_update=datetime(2026, 1, 20, 10, 0, 0),
    )

    technical = build_technical_data(curr, prev)
    tt = trend_mod._derive_trend_table(technical, evaluation=None)

    assert tt["TLS-Schwächen"][0] == 1
    assert tt["TLS-Schwächen"][1] == 1
    assert tt["TLS-Schwächen"][2] == "stabil"


def test_legacy_no_data_path(styles):
    elements = []
    trend_mod.create_trend_section(elements=elements, styles=styles, trend_text="", legacy_mode=True)
    # find legacy message
    texts = [getattr(e, "text", "") for e in elements if isinstance(e, Paragraph)]
    assert any("Keine historischen Daten" in t for t in texts), "Legacy message expected"
