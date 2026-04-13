import re
from reportlab.platypus import Table, Paragraph
from shodan_report.pdf.styles import create_styles, create_theme
from shodan_report.pdf.sections.cve_overview import create_cve_overview_section


def _make_styles():
    theme = create_theme("#1a365d", "#2d3748")
    return create_styles(theme)


def _paragraph_text(p) -> str:
    """Extrahiert Plain-Text aus Paragraph oder verschachtelter Table."""
    if isinstance(p, Paragraph):
        try:
            return str(p.getPlainText())
        except Exception:
            return str(getattr(p, "text", ""))
    if isinstance(p, Table):
        # Traverse into first cell to find the numeric paragraph
        try:
            cell = p._cellvalues[0][0]
            return _paragraph_text(cell)
        except Exception:
            pass
    return ""


def _all_para_texts_in_elements(elements) -> list:
    """Extrahiert rekursiv alle Paragraph-Texte aus elements (inkl. verschachtelter Tables)."""
    texts = []
    for e in elements:
        if isinstance(e, Paragraph):
            texts.append(_paragraph_text(e))
        elif isinstance(e, Table):
            for row in (getattr(e, "_cellvalues", None) or []):
                for cell in row:
                    texts.extend(_all_para_texts_in_elements([cell]))
    return texts


def _extract_counts_from_risk_table(tbl: Table):
    """Extrahiert die 5 Zähler aus der KPI-Karten-Zeile.

    Jede Zelle der äußeren Tabelle ist eine innere Table (card).
    Zeile 0 der inneren Table = Zahl-Paragraph.
    """
    cells = getattr(tbl, "_cellvalues", [[]])[0]
    counts = []
    for c in cells:
        if isinstance(c, Table):
            # inner card: row 0 = number paragraph
            try:
                c = c._cellvalues[0][0]
            except (IndexError, AttributeError):
                pass
        txt = _paragraph_text(c)
        nums = re.findall(r"\d+", txt)
        counts.append(int(nums[0]) if nums else 0)
    return counts


def _find_detailed_table(elements):
    """Findet die detaillierte CVE-Tabelle (5 Spalten: CVE|CVSS|Dienst|Exploit|Relevanz)."""
    for t in elements:
        if isinstance(t, Table):
            try:
                header = t._cellvalues[0]
                if len(header) == 5:
                    texts = [_paragraph_text(c).upper() for c in header]
                    if any("CVE" in tx for tx in texts):
                        return t
            except Exception:
                continue
    return None


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
    # Column order: CVE=0 | CVSS-badge=1 | DIENST=2 | EXPLOIT-STATUS=3 | RELEVANZ-badge=4
    first_row = detailed._cellvalues[1]

    # CVE id (column 0)
    cve_txt = _paragraph_text(first_row[0])
    assert "CVE-2023-MED_A" in cve_txt

    # CVSS shown as numeric string (column 1 is a badge Table)
    cvss_txt = _paragraph_text(first_row[1])
    assert "7.5" in cvss_txt

    # Dienst (service) should include 'nginx' (column 2)
    svc_txt = _paragraph_text(first_row[2])
    assert "nginx" in svc_txt.lower()

    # Exploit-status mapping: 'public' -> 'öffentlich bekannt' (column 3)
    exploit_txt = _paragraph_text(first_row[3])
    assert "öffentlich" in exploit_txt.lower()

    # Relevance: current code classifies 7.5 as 'hoch' (column 4 is a badge Table)
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

    # Find detailed table (5-spaltig)
    detailed = _find_detailed_table(elements)
    assert detailed is not None, "Detailed CVE table not found"

    # column 4 = Relevanz-Badge (Table) — extract text from nested badge Table
    rels = []
    for row in detailed._cellvalues[1:]:
        rels.append(_paragraph_text(row[4]).lower())

    # Expect labels: kritisch / hoch / mittel (medium) / niedrig / unbekannt
    assert any("kritisch" in r for r in rels), f"no 'kritisch' in {rels}"
    assert any("hoch" in r for r in rels), f"no 'hoch' in {rels}"
    # 'medium' is used in the badge label instead of 'mittel'
    assert any("mittel" in r or "medium" in r for r in rels), f"no 'mittel/medium' in {rels}"
    assert any("niedrig" in r for r in rels), f"no 'niedrig' in {rels}"
    assert any("unbekannt" in r for r in rels), f"no 'unbekannt' in {rels}"

    # The implementation appends a final evaluation box containing "Vollständige CVE-Liste"
    all_texts = _all_para_texts_in_elements(elements)
    assert any("vollst" in t.lower() for t in all_texts), (
        "Final evaluation box with CVE-Liste text not found"
    )


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

    detailed = _find_detailed_table(elements)
    assert detailed is not None, "Detailed CVE table not found"

    # Column order: CVE=0 | CVSS=1 | DIENST=2 | EXPLOIT=3 | RELEVANZ=4
    first_row = detailed._cellvalues[1]
    svc_txt = _paragraph_text(first_row[2])
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

    all_texts = _all_para_texts_in_elements(elements)
    note = [t for t in all_texts if "technische verifikation" in t.lower()]
    assert note, "Evaluation note not found"


def test_cve_hint_text_when_list_truncated(monkeypatch):
    """Wenn mehr CVEs vorliegen als angezeigt werden, erscheint der
    kundenfreundliche Hinweis 'Vollständige Liste auf Anfrage verfügbar' (30.03.2026)."""
    styles = _make_styles()
    elements = []
    technical_json = {"services": [], "vulns": [f"CVE-2025-{i:04d}" for i in range(10)]}

    enriched = [
        {"id": f"CVE-2025-{i:04d}", "cvss": 7.0, "ports": [], "service": "Various",
         "summary": "", "exploit_status": "none"}
        for i in range(10)
    ]

    import shodan_report.pdf.sections.cve_overview as mod
    monkeypatch.setattr(mod, "enrich_cves", lambda ids, technical_json=None, lookup_nvd=False: enriched)

    create_cve_overview_section(elements, styles, technical_json)

    all_texts = _all_para_texts_in_elements(elements)
    # Implementation uses "Vollständige CVE-Liste auf Anfrage verfügbar."
    found = any("Liste auf Anfrage verf" in t for t in all_texts)
    assert found, "Hinweistext 'Liste auf Anfrage verfügbar' fehlt beim Truncate"
