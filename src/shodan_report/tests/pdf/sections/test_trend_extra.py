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


def test_derive_trend_table_uses_enriched_cves_for_high_risk():
    tech = {
        "open_ports": [{"port": 443}],
        "cve_enriched": [
            {"id": "CVE-1", "cvss": 9.8},
            {"id": "CVE-2", "cvss": 6.5},
        ],
        "previous_metrics": {
            "Öffentliche Ports": 1,
            "Kritische Services": 0,
            "Hochrisiko-CVEs": 1,
            "TLS-Schwächen": 0,
        },
    }

    tt = trend_mod._derive_trend_table(tech, evaluation=None)

    assert tt["Hochrisiko-CVEs"][1] == 1


def test_derive_trend_table_dedupes_high_risk_cves():
    tech = {
        "open_ports": [{"port": 443}],
        "cve_enriched": [
            {"id": "CVE-CRIT", "cvss": 9.8},
            {"id": "CVE-CRIT", "cvss": 9.1},
        ],
        "vulnerabilities": [{"id": "CVE-CRIT", "cvss": 9.8}],
        "previous_metrics": {
            "Öffentliche Ports": 1,
            "Kritische Services": 0,
            "Hochrisiko-CVEs": 1,
            "TLS-Schwächen": 0,
        },
    }

    tt = trend_mod._derive_trend_table(tech, evaluation=None)

    assert tt["Hochrisiko-CVEs"][1] == 1


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

    # Suche nach KPI-Karten-Table (5 Spalten, Titel wie "VORMONAT", "AKTUELL")
    kpi_table = next((e for e in elements if isinstance(e, Table) and getattr(e, '_ncols', 0) == 5), None)
    assert kpi_table is not None, "KPI-Karten-Table sollte gerendert werden"
    # Prüfe, dass die Titel stimmen
    data = getattr(kpi_table, '_cellvalues', None) or getattr(kpi_table, 'getPlainData', lambda: None)()
    header_row = data[0]
    header_texts = [getattr(cell[0], 'text', str(cell[0])) if isinstance(cell, list) else getattr(cell, 'text', str(cell)) for cell in header_row]
    assert any('VORMONAT' in t for t in header_texts), 'KPI-Karten sollten "VORMONAT" enthalten'
    assert any('AKTUELL' in t for t in header_texts), 'KPI-Karten sollten "AKTUELL" enthalten'


def test_create_trend_section_derives_table_from_technical_json(styles):
    elements = []
    # Testdaten so wählen, dass Vergleichstabelle sicher erzeugt wird
    technical_json = {
        "open_ports": [
            {"port": 443, "product": "HTTP", "is_ssl": False, "ssl_info": {"has_weak_cipher": True}},
            {"port": 80, "product": "HTTP", "is_ssl": False, "ssl_info": None},
        ],
        "critical_services": ["ssh"],
        "vulnerabilities": [{"id": "CVE-1", "cvss": 9.0}],
        "tls_weaknesses": ["expired_cert"],
        "previous_metrics": {
            "Öffentliche Ports": 1,
            "Kritische Services": 0,
            "Hochrisiko-CVEs": 0,
            "TLS-Schwächen": 0,
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
    # Suche nach einer Tabelle mit 4 Spalten (auch in verschachtelten Tables)
    def _find_table_ncols(elist, ncols):
        from reportlab.platypus import KeepTogether
        for e in elist:
            if isinstance(e, Table):
                if getattr(e, '_ncols', 0) == ncols:
                    return e
                for row in (getattr(e, '_cellvalues', None) or []):
                    for cell in (row if isinstance(row, (list, tuple)) else [row]):
                        items = cell if isinstance(cell, (list, tuple)) else [cell]
                        result = _find_table_ncols(items, ncols)
                        if result:
                            return result
            elif isinstance(e, KeepTogether):
                result = _find_table_ncols(getattr(e, '_content', []) or [], ncols)
                if result:
                    return result
        return None

    cmp_table = _find_table_ncols(elements, 4)
    assert cmp_table is not None, "Vergleichstabelle sollte gerendert werden"
    # Prüfe, ob die Zeile für TLS-Schwächen enthalten ist
    data = getattr(cmp_table, '_cellvalues', None) or getattr(cmp_table, 'getPlainData', lambda: None)()
    def _cell_text(cell):
        if isinstance(cell, (list, tuple)) and cell:
            cell = cell[0]
        return getattr(cell, "text", str(cell))
    tls_row = None
    for row in data:
        if any("Zert" in _cell_text(c) or "TLS" in _cell_text(c) for c in row):
            tls_row = [_cell_text(c) for c in row]
            break
    assert tls_row is not None, "TLS/Zertifikat row should be present"


def test_trend_section_includes_interpretation_text(styles):
    elements = []
    # Testdaten so wählen, dass Interpretation sicher erzeugt wird und aus technical_json abgeleitet wird
    technical_json = {
        "open_ports": [
            {"port": 443, "product": "HTTP", "is_ssl": False, "ssl_info": {"has_weak_cipher": True}},
            {"port": 80, "product": "HTTP", "is_ssl": False, "ssl_info": None},
        ],
        "critical_services": ["ssh"],
        "vulnerabilities": [{"id": "CVE-1", "cvss": 9.0}],
        "tls_weaknesses": ["expired_cert"],
        "previous_metrics": {
            "Öffentliche Ports": 1,
            "Kritische Services": 0,
            "Hochrisiko-CVEs": 0,
            "TLS-Schwächen": 0,
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
    # Suche nach Paragraphs mit "Interpretation:"
    def find_paragraphs(elist):
        from reportlab.platypus import Paragraph, Table, KeepTogether
        found = []
        for e in elist:
            if isinstance(e, Paragraph):
                found.append(e)
            elif isinstance(e, Table):
                for row in (getattr(e, "_cellvalues", None) or []):
                    for cell in (row if isinstance(row, (list, tuple)) else [row]):
                        items = cell if isinstance(cell, (list, tuple)) else [cell]
                        found.extend(find_paragraphs(items))
            elif isinstance(e, KeepTogether):
                found.extend(find_paragraphs(getattr(e, "_content", []) or []))
        return found
    texts = [getattr(e, "text", "") for e in find_paragraphs(elements)]
    assert any("Interpretation:" in t for t in texts), f"Interpretation fehlt: {texts}"


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


def test_no_data_view_shows_baseline_with_exposure_score(styles):
    """Erster Report: Baseline-Zeile mit Exposure-Score wird gerendert (30.03.2026)."""
    elements = []
    trend_mod.create_trend_section(
        elements=elements,
        styles=styles,
        trend_text="",
        evaluation={"exposure_score": 3},
    )
    texts = [getattr(e, "text", "") for e in elements if isinstance(e, Paragraph)]
    assert any("Exposure-Level 3/5" in t for t in texts), "Baseline mit Exposure-Score fehlt"
    assert any("Angriffsflächen verändern sich monatlich" in t for t in texts), "Drei-Punkte-Block fehlt"
    assert any("Frühwarnung statt Reaktion" in t for t in texts), "Dritter Punkt fehlt"


def test_metrics_context_appears_in_comparison_view(styles):
    """Folgereport: 'Was die Kennzahlen bedeuten' erscheint wenn Tabelle Werte enthält (30.03.2026)."""
    elements = []
    # Testdaten so wählen, dass Metriken-Kontext sicher erscheint und aus technical_json abgeleitet wird
    technical_json = {
        "open_ports": [
            {"port": 443, "product": "HTTP", "is_ssl": False, "ssl_info": {"has_weak_cipher": True}},
            {"port": 80, "product": "HTTP", "is_ssl": False, "ssl_info": None},
        ],
        "critical_services": ["ssh"],
        "vulnerabilities": [{"id": "CVE-1", "cvss": 9.0}],
        "tls_weaknesses": ["expired_cert"],
        "previous_metrics": {
            "Öffentliche Ports": 1,
            "Kritische Services": 0,
            "Hochrisiko-CVEs": 0,
            "TLS-Schwächen": 0,
        },
    }
    trend_mod.create_trend_section(
        elements=elements,
        styles={**styles, "heading3": styles["heading2"], "small": styles["normal"]},
        trend_text="",
        compare_month="Februar 2026",
        technical_json=technical_json,
        evaluation=None,
    )
    # Suche nach Paragraphs mit "Was die Kennzahlen bedeuten"
    def find_paragraphs(elist):
        from reportlab.platypus import Paragraph, Table, KeepTogether
        found = []
        for e in elist:
            if isinstance(e, Paragraph):
                found.append(e)
            elif isinstance(e, Table):
                for row in (getattr(e, "_cellvalues", None) or []):
                    for cell in (row if isinstance(row, (list, tuple)) else [row]):
                        items = cell if isinstance(cell, (list, tuple)) else [cell]
                        found.extend(find_paragraphs(items))
            elif isinstance(e, KeepTogether):
                found.extend(find_paragraphs(getattr(e, "_content", []) or []))
        return found
    texts = [getattr(e, "text", "") for e in find_paragraphs(elements)]
    assert any("Was die Kennzahlen bedeuten" in t for t in texts), f"Metriken-Erklärungsblock fehlt: {texts}"
