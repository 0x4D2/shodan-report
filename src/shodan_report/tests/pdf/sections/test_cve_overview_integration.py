import re
from reportlab.platypus import Table, Paragraph
from shodan_report.pdf.styles import create_styles, create_theme
from shodan_report.pdf.sections.cve_overview import create_cve_overview_section


def _make_styles():
    theme = create_theme("#1a365d", "#2d3748")
    return create_styles(theme)


def _paragraph_text(p: Paragraph) -> str:
    try:
        return str(p.getPlainText())
    except Exception:
        return str(p)


def _extract_counts_from_risk_table(tbl: Table):
    # risk table is single-row with 5 Paragraph cells (label + count)
    cells = getattr(tbl, "_cellvalues", [[]])[0]
    counts = []
    for c in cells:
        txt = _paragraph_text(c)
        nums = re.findall(r"\d+", txt)
        counts.append(int(nums[0]) if nums else 0)
    return counts


def test_cve_overview_counts_and_classification(monkeypatch):
    """Integration-style test: when enrich returns mixed CVSS/exploit statuses,
    the risk overview box counts and detailed table classification follow the
    expected business rules (kritisch/hoch/mittel/niedrig/unbekannt).
    """
    styles = _make_styles()
    elements = []

    # Prepare technical json mapping port 80 -> nginx for service label resolution
    technical_json = {"services": [{"port": 80, "product": "nginx"}]}

    # Simulate enrich_cves returning various CVEs with CVSS values and exploit flags
    enriched = [
        {"id": "CVE-2023-CRIT", "cvss": 9.8, "ports": [22], "service": "ssh", "summary": "", "exploit_status": "none"},
        {"id": "CVE-2023-MED_A", "cvss": 7.5, "ports": [80], "service": "nginx", "summary": "", "exploit_status": "public"},
        {"id": "CVE-2023-MED_B", "cvss": 4.5, "ports": [], "service": "Various", "summary": "", "exploit_status": "unknown"},
        {"id": "CVE-2023-LOW", "cvss": 0.5, "ports": [], "service": "Various", "summary": "", "exploit_status": "none"},
        {"id": "CVE-2023-UNK", "cvss": None, "ports": [], "service": "Various", "summary": "", "exploit_status": "unknown"},
    ]

    # Monkeypatch the internal enricher used by create_cve_overview_section
    import shodan_report.pdf.sections.cve_overview as mod

    monkeypatch.setattr(mod, "enrich_cves", lambda ids, technical_json=None, lookup_nvd=False: enriched)

    # Call the high-level builder
    create_cve_overview_section(elements, styles, technical_json)

    # Find first Table (risk overview) and validate counts
    tables = [e for e in elements if isinstance(e, Table)]
    assert tables, "No Table elements created"

    # risk overview is expected as the first Table appended
    risk_table = tables[0]
    counts = _extract_counts_from_risk_table(risk_table)

    # Current classification in code: 9.0+ crit, 7.0-8.99 high, 4.0-6.99 medium
    # For CVSSs [9.8,7.5,4.5,0.5,None] the counts should be [1,1,1,1,1]
    assert counts == [1, 1, 1, 1, 1]


def test_detailed_table_rows_contain_expected_values(monkeypatch):
    """Verify that the detailed CVE table contains a row for nginx/CVE-2023-MED_A
    with the expected CVSS, exploit mapping and relevance text (localized).
    """
    styles = _make_styles()
    elements = []

    technical_json = {"services": [{"port": 80, "product": "nginx"}]}

    enriched = [
        {"id": "CVE-2023-MED_A", "cvss": 7.5, "ports": [80], "service": "nginx", "summary": "", "exploit_status": "public"},
    ]

    import shodan_report.pdf.sections.cve_overview as mod
    monkeypatch.setattr(mod, "enrich_cves", lambda ids, technical_json=None, lookup_nvd=False: enriched)

    create_cve_overview_section(elements, styles, technical_json)

    # Find the detailed table (it has header row with 'CVE')
    tables = [t for t in elements if isinstance(t, Table)]
    assert tables, "No tables generated"

    # find the detailed table by looking for header cell text containing 'CVSS' or 'CVE'
    detailed = None
    for t in tables:
        try:
            header = t._cellvalues[0]
            texts = [
                (c.getPlainText() if hasattr(c, 'getPlainText') else str(c)).lower()
                for c in header
            ]
            if any('cvss' in txt or 'cve' in txt for txt in texts):
                detailed = t
                break
        except Exception:
            continue

    assert detailed is not None, "Detailed CVE table not found"

    # The first data row is at index 1
    first_row = detailed._cellvalues[1]

    # Dienst (service) should include 'nginx'
    svc_txt = _paragraph_text(first_row[0])
    assert "nginx" in svc_txt.lower()

    # CVE id
    cve_txt = _paragraph_text(first_row[1])
    assert "CVE-2023-MED_A" in cve_txt

    # CVSS shown as numeric string
    cvss_txt = _paragraph_text(first_row[2])
    assert "7.5" in cvss_txt

    # Exploit-status mapping: 'public' -> 'öffentlich bekannt'
    exploit_txt = _paragraph_text(first_row[3])
    assert "öffentlich" in exploit_txt.lower()

    # Relevance: current code classifies 7.5 as 'hoch'
    rel_txt = _paragraph_text(first_row[4])
    assert "hoch" in rel_txt.lower()


def test_relevance_thresholds_and_exploit_summary(monkeypatch):
    """Ensure relevance buckets and exploit summary reflect a mixed set of CVSS values
    and exploit flags (simulates CISA-public entries via the enricher output).
    """
    styles = _make_styles()
    elements = []

    technical_json = {"services": [{"port": 80, "product": "nginx"}]}

    enriched = [
        {"id": "CVE-CRIT", "cvss": 9.5, "ports": [80], "service": "nginx", "summary": "", "exploit_status": "public"},
        {"id": "CVE-HIGH", "cvss": 8.1, "ports": [], "service": "Various", "summary": "", "exploit_status": "private"},
        {"id": "CVE-MED", "cvss": 5.0, "ports": [], "service": "Various", "summary": "", "exploit_status": "none"},
        {"id": "CVE-LOW", "cvss": 2.0, "ports": [], "service": "Various", "summary": "", "exploit_status": "none"},
        {"id": "CVE-UNK", "cvss": None, "ports": [], "service": "Various", "summary": "", "exploit_status": "unknown"},
    ]

    import shodan_report.pdf.sections.cve_overview as mod
    monkeypatch.setattr(mod, "enrich_cves", lambda ids, technical_json=None, lookup_nvd=False: enriched)

    create_cve_overview_section(elements, styles, technical_json)

    # Find detailed table and examine relevance column values in order
    tables = [t for t in elements if isinstance(t, Table)]
    assert tables
    detailed = tables[-1]  # detailed table is appended after risk box
    # extract relevance texts from each data row
    rels = []
    for row in detailed._cellvalues[1:]:
        rels.append(_paragraph_text(row[4]).lower())

    # Expect ordering by CVSS desc: CRIT, HIGH, MED, LOW, UNK
    assert any("kritisch" in r for r in rels), f"no 'kritisch' in {rels}"
    assert any("hoch" in r for r in rels), f"no 'hoch' in {rels}"
    assert any("mittel" in r for r in rels), f"no 'mittel' in {rels}"
    assert any("niedrig" in r for r in rels), f"no 'niedrig' in {rels}"
    assert any("unbekannt" in r for r in rels), f"no 'unbekannt' in {rels}"

    # The implementation currently appends a final evaluation paragraph which
    # contains a count of public exploits; assert that text exists.
    paras = [p for p in elements if isinstance(p, Paragraph)]
    final_paras = [p for p in paras if 'öffentliche exploits' in _paragraph_text(p).lower()]
    assert final_paras, "Final evaluation paragraph with exploit summary not found"
    assert 'öffentliche exploits' in _paragraph_text(final_paras[0]).lower()


def test_service_indicator_renders_osint_label(monkeypatch):
    styles = _make_styles()
    elements = []

    technical_json = {"services": [{"port": 3306, "product": "MySQL"}]}

    enriched = [
        {
            "id": "CVE-2024-OSINT",
            "cvss": 4.9,
            "ports": [3306],
            "service": "MySQL",
            "summary": "",
            "exploit_status": "unknown",
            "service_indicator": {"matched_by": "nvd_cpe", "confidence": "low", "label": "MySQL"},
        }
    ]

    import shodan_report.pdf.sections.cve_overview as mod
    monkeypatch.setattr(mod, "enrich_cves", lambda ids, technical_json=None, lookup_nvd=False: enriched)

    create_cve_overview_section(elements, styles, technical_json)

    tables = [t for t in elements if isinstance(t, Table)]
    assert tables, "No tables generated"
    detailed = tables[-1]

    first_row = detailed._cellvalues[1]
    svc_txt = _paragraph_text(first_row[0])
    assert "mysql" in svc_txt.lower()
    assert "osint" in svc_txt.lower()


def test_evaluation_note_is_appended(monkeypatch):
    styles = _make_styles()
    elements = []

    technical_json = {"services": []}
    enriched = [
        {"id": "CVE-2024-1", "cvss": 4.0, "ports": [], "service": "Various", "summary": "", "exploit_status": "unknown"}
    ]

    import shodan_report.pdf.sections.cve_overview as mod
    monkeypatch.setattr(mod, "enrich_cves", lambda ids, technical_json=None, lookup_nvd=False: enriched)

    create_cve_overview_section(elements, styles, technical_json)

    paras = [p for p in elements if isinstance(p, Paragraph)]
    note = [p for p in paras if "technische verifikation" in _paragraph_text(p).lower()]
    assert note, "Evaluation note not found"
