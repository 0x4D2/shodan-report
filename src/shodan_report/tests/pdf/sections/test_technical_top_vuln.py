from shodan_report.pdf.sections.data.technical_data import prepare_technical_detail
from reportlab.platypus import Paragraph, Table


def test_top_vuln_and_risk_escalation_for_db_port():
    technical_json = {
        "open_ports": [
            {"port": 3306, "service": {"product": "MySQL"}, "vulnerabilities": [{"id": "CVE-2025-0001", "cvss": 6.5}]},
            {"port": 80, "service": {"product": "HTTP"}, "vulnerabilities": [{"id": "CVE-2025-0002", "cvss": 7.5}]},
        ],
    }
    result = prepare_technical_detail(technical_json, {})
    services = {s["port"]: s for s in result["services"]}
    # DB port should be escalated to 'hoch' because it's a DB port
    assert services[3306]["risk"] == "hoch"
    # top_vuln for port 80 should be CVE-2025-0002 with cvss 7.5
    assert services[80]["top_vuln"]["id"] == "CVE-2025-0002"
    assert services[80]["top_vuln"]["cvss"] == 7.5


# ── EOL-Tag Warning Box ────────────────────────────────────────────────────

def _make_styles():
    from shodan_report.pdf.styles import create_styles, create_theme
    return create_styles(create_theme("#1a365d", "#2d3748"))


def test_eol_tag_renders_warning_box():
    """eol-product tag produces a Table (warning box) in the elements list."""
    from shodan_report.pdf.sections.technical import _render_shodan_tags_warning
    elements = []
    styles = _make_styles()
    tj = {"tags": ["eol-product"], "open_ports": []}
    _render_shodan_tags_warning(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 1
    # box content should mention severity
    flat_text = " ".join(
        str(getattr(p, "text", "")) for row in tables[0]._cellvalues for cell in row
        for p in (cell if isinstance(cell, list) else [cell])
        if hasattr(p, "text")
    )
    assert "HOCH" in flat_text
    assert "End-of-Life" in flat_text


def test_doublepulsar_renders_critical_box():
    """doublepulsar tag produces KRITISCH severity box."""
    from shodan_report.pdf.sections.technical import _render_shodan_tags_warning
    elements = []
    styles = _make_styles()
    tj = {"tags": ["doublepulsar"], "open_ports": []}
    _render_shodan_tags_warning(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 1
    flat_text = " ".join(
        str(getattr(p, "text", "")) for row in tables[0]._cellvalues for cell in row
        for p in (cell if isinstance(cell, list) else [cell])
        if hasattr(p, "text")
    )
    assert "KRITISCH" in flat_text


def test_no_box_for_unknown_or_informational_tags():
    """cloud/vpn tags and unknown tags produce no warning box."""
    from shodan_report.pdf.sections.technical import _render_shodan_tags_warning
    elements = []
    styles = _make_styles()
    tj = {"tags": ["cloud", "vpn", "some-unknown-tag"], "open_ports": []}
    _render_shodan_tags_warning(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 0


def test_no_tags_produces_no_box():
    """Empty or absent tags list produces nothing."""
    from shodan_report.pdf.sections.technical import _render_shodan_tags_warning
    elements = []
    styles = _make_styles()
    _render_shodan_tags_warning(elements, styles, {})
    assert len(elements) == 0


def test_eol_tag_not_duplicated_in_metadata():
    """eol-product must NOT appear in the plain-text metadata items list."""
    from shodan_report.pdf.sections.technical import _extract_metadata_items
    items = _extract_metadata_items({"tags": ["eol-product", "cloud"]})
    tags_line = next((i for i in items if i.startswith("Tags:")), None)
    # eol-product should be absent from the text line (it has a severity)
    if tags_line:
        assert "eol-product" not in tags_line
    # cloud (informational) is OK to appear

