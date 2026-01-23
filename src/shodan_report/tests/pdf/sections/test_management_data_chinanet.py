import json
from pathlib import Path

from shodan_report.pdf.sections.data.management_data import prepare_management_data
from shodan_report.pdf.sections.management import create_management_section
from shodan_report.pdf.styles import create_styles, create_theme
from reportlab.platypus import Paragraph
from shodan_report.evaluation import Evaluation, RiskLevel
from shodan_report.pdf.pdf_generator import generate_pdf
from shodan_report.reporting.management_text import generate_management_text
from shodan_report.evaluation.risk_prioritization import BusinessRisk
import pytest


def test_prepare_management_data_chinanet_snapshot():
    # locate project root and snapshot file
    repo_root = Path(__file__).resolve().parents[5]
    snap_path = repo_root / "snapshots" / "CHINANET" / "2026-01_111.170.152.60.json"
    assert snap_path.exists(), f"Snapshot not found: {snap_path}"

    with snap_path.open("r", encoding="utf-8") as fh:
        technical_json = json.load(fh)

    # minimal evaluation object (no extra CVEs)
    evaluation = {"cves": []}

    mdata = prepare_management_data(technical_json, evaluation)

    # expected values derived from snapshot
    expected_unique = set(technical_json.get("vulns", []) or [])
    expected_ports = len(technical_json.get("open_ports", []) or [])

    # verify numbers used by the management text
    assert mdata["cve_count"] == len(expected_unique)
    assert set(mdata["unique_cves"]) == expected_unique
    assert mdata["total_ports"] == expected_ports


def test_management_section_includes_cve_and_port_counts():
    repo_root = Path(__file__).resolve().parents[5]
    snap_path = repo_root / "snapshots" / "CHINANET" / "2026-01_111.170.152.60.json"
    with snap_path.open("r", encoding="utf-8") as fh:
        technical_json = json.load(fh)

    # prepare evaluation and styles
    evaluation = Evaluation(ip=technical_json.get("ip", ""), risk=RiskLevel.CRITICAL, critical_points=[])
    theme = create_theme("#1a365d", "#2d3748")
    styles = create_styles(theme)

    elements = []
    create_management_section(
        elements=elements,
        styles=styles,
        technical_json=technical_json,
        evaluation=evaluation,
        business_risk="CRITICAL",
    )

    paragraph_texts = [str(e.getPlainText()) for e in elements if isinstance(e, Paragraph)]

    # find intro and cve paragraphs (no counts on page 1)
    intro_found = any("öffentlich erreichbare Dienste identifiziert." in t for t in paragraph_texts)
    cve_found = any("Bekannte Schwachstellen sind im technischen Anhang dokumentiert." in t for t in paragraph_texts)

    assert intro_found, "Intro paragraph without counts not found"
    assert cve_found, "CVE summary without counts not found"


def test_rendered_pdf_contains_expected_numbers(tmp_path):
    PyPDF2 = pytest.importorskip("PyPDF2")
    repo_root = Path(__file__).resolve().parents[5]
    snap_path = repo_root / "snapshots" / "CHINANET" / "2026-01_111.170.152.60.json"
    with snap_path.open("r", encoding="utf-8") as fh:
        technical_json = json.load(fh)

    ip = technical_json.get("ip")
    # create evaluation object for management text generation
    evaluation_obj = Evaluation(ip=ip, risk=RiskLevel.CRITICAL, critical_points=[])
    mgmt_text = generate_management_text(BusinessRisk.CRITICAL, evaluation_obj, technical_json=technical_json)

    # generate PDF into temporary output dir
    out_dir = tmp_path / "reports"
    pdf_path = generate_pdf(
        customer_name="CHINANET",
        month="2026-01",
        ip=ip,
        management_text=mgmt_text,
        trend_text="",
        technical_json=technical_json,
        evaluation={"ip": ip, "risk": "risklevel.critical", "critical_points": []},
        business_risk="CRITICAL",
        output_dir=out_dir,
    )

    assert pdf_path.exists()

    # extract text from PDF
    from PyPDF2 import PdfReader

    reader = PdfReader(str(pdf_path))
    full_text = "\n".join(p.extract_text() or "" for p in reader.pages)

    assert "öffentlich erreichbare Dienste identifiziert." in full_text
    assert "Bekannte Schwachstellen sind im technischen Anhang dokumentiert." in full_text


def test_management_text_flags_and_critical_message():
    """Simulate an evaluation that flags critical problems and verify
    the prepared management data would trigger the critical message.
    """
    with open(Path(__file__).resolve().parents[5] / "snapshots" / "CHINANET" / "2026-01_111.170.152.60.json", "r", encoding="utf-8") as fh:
        technical_json = json.load(fh)

    # simulate an evaluation with critical points and risk
    evaluation = {
        "cves": [],
        "critical_points": ["root_login", "outdated_service"],
        "critical_points_count": 2,
        "risk": "risklevel.critical",
    }

    mdata = prepare_management_data(technical_json, evaluation)

    assert mdata["critical_points_count"] == 2
    assert mdata["risk_level"] == "critical"
