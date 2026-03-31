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


# ── TLS Verified Warning Boxes ────────────────────────────────────────────

def _flat_box_text(tables):
    """Extract all paragraph text from Table cells in elements list."""
    return " ".join(
        str(getattr(p, "text", ""))
        for t in tables
        for row in t._cellvalues
        for cell in row
        for p in (cell if isinstance(cell, list) else [cell])
        if hasattr(p, "text")
    )


def test_tls_tlsv1_enabled_renders_hoch_box():
    """TLSv1 without '-' prefix → HOCH warning box with VERIFIED label."""
    from shodan_report.pdf.sections.technical import _render_tls_warnings
    elements = []
    styles = _make_styles()
    tj = {"services": [{"port": 443, "ssl_info": {"versions": ["TLSv1", "TLSv1.2", "-SSLv3"]}}]}
    _render_tls_warnings(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 1
    text = _flat_box_text(tables)
    assert "VERIFIED" in text
    assert "HOCH" in text
    assert "443" in text


def test_tls_tlsv11_enabled_renders_mittel_box():
    """TLSv1.1 without '-' prefix → MITTEL warning box."""
    from shodan_report.pdf.sections.technical import _render_tls_warnings
    elements = []
    styles = _make_styles()
    tj = {"services": [{"port": 8443, "ssl_info": {"versions": ["TLSv1.1", "TLSv1.2"]}}]}
    _render_tls_warnings(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 1
    text = _flat_box_text(tables)
    assert "VERIFIED" in text
    assert "MITTEL" in text


def test_tls_sslv3_renders_kritisch_box():
    """SSLv3 without '-' prefix → KRITISCH warning box."""
    from shodan_report.pdf.sections.technical import _render_tls_warnings
    elements = []
    styles = _make_styles()
    tj = {"services": [{"port": 443, "ssl_info": {"versions": ["SSLv3", "TLSv1.2"]}}]}
    _render_tls_warnings(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 1
    text = _flat_box_text(tables)
    assert "KRITISCH" in text


def test_tls_disabled_prefix_no_box():
    """All insecure protocols have '-' prefix (disabled) → no warning box."""
    from shodan_report.pdf.sections.technical import _render_tls_warnings
    elements = []
    styles = _make_styles()
    tj = {"services": [{"port": 443, "ssl_info": {"versions": ["-TLSv1", "-TLSv1.1", "-SSLv2", "-SSLv3", "TLSv1.2", "TLSv1.3"]}}]}
    _render_tls_warnings(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 0


def test_tls_no_ssl_info_no_box():
    """Service without ssl_info → no crash, no warning box."""
    from shodan_report.pdf.sections.technical import _render_tls_warnings
    elements = []
    styles = _make_styles()
    tj = {"services": [{"port": 80}]}
    _render_tls_warnings(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 0


def test_tls_empty_versions_no_box():
    """ssl_info with empty versions list → no warning box."""
    from shodan_report.pdf.sections.technical import _render_tls_warnings
    elements = []
    styles = _make_styles()
    tj = {"services": [{"port": 3389, "ssl_info": {"versions": []}}]}
    _render_tls_warnings(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 0


def test_tls_multiple_protocols_sorted_by_severity():
    """Multiple insecure protocols → sorted KRITISCH before HOCH before MITTEL."""
    from shodan_report.pdf.sections.technical import _render_tls_warnings
    elements = []
    styles = _make_styles()
    tj = {"services": [{"port": 443, "ssl_info": {"versions": ["TLSv1.1", "SSLv3", "TLSv1"]}}]}
    _render_tls_warnings(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 3
    texts = [_flat_box_text([t]) for t in tables]
    # SSLv3 (kritisch) must appear before TLSv1 (hoch) before TLSv1.1 (mittel)
    idx_kritisch = next(i for i, t in enumerate(texts) if "KRITISCH" in t)
    idx_hoch = next(i for i, t in enumerate(texts) if "HOCH" in t)
    idx_mittel = next(i for i, t in enumerate(texts) if "MITTEL" in t)
    assert idx_kritisch < idx_hoch < idx_mittel


def test_tls_deduplicates_across_services():
    """Same protocol on two services → single box listing both ports."""
    from shodan_report.pdf.sections.technical import _render_tls_warnings
    elements = []
    styles = _make_styles()
    tj = {"services": [
        {"port": 443,  "ssl_info": {"versions": ["TLSv1"]}},
        {"port": 8443, "ssl_info": {"versions": ["TLSv1"]}},
    ]}
    _render_tls_warnings(elements, styles, tj)
    tables = [e for e in elements if isinstance(e, Table)]
    assert len(tables) == 1
    text = _flat_box_text(tables)
    assert "443" in text
    assert "8443" in text

