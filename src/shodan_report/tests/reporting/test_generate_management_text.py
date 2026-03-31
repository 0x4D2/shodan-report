import pytest

from shodan_report.reporting.management_text import generate_management_text
from shodan_report.evaluation.risk_prioritization import BusinessRisk
from shodan_report.evaluation.evaluation import Evaluation, RiskLevel


@pytest.mark.parametrize(
    "business_risk, eval_risk, critical_points, expected_phrases",
    [
        (
            BusinessRisk.MONITOR,
            RiskLevel.LOW,
            [],
            ["ist stabil", "Kein unmittelbarer Handlungsbedarf"],
        ),
        (
            BusinessRisk.ATTENTION,
            RiskLevel.MEDIUM,
            ["Viele offene Dienste: 5", "Veraltete/anfällige Version: nginx 1.0"],
            ["erhöhte Risiken", "IT-Betrieb"],
        ),
        (
            BusinessRisk.CRITICAL,
            RiskLevel.HIGH,
            ["Kritischer Dienst gefunden: ssh auf Port 22"],
            ["Risikoindikatoren", "Maßnahmenplan"],
        ),
    ],
)
def test_generate_management_text_variants(
    business_risk, eval_risk, critical_points, expected_phrases
):
    evaluation = Evaluation(
        ip="1.2.3.4", risk=eval_risk, critical_points=critical_points
    )
    text = generate_management_text(business_risk, evaluation)

    for phrase in expected_phrases:
        assert phrase in text


def test_business_risk_parameter_takes_precedence():
    # CRITICAL ohne technical_json → generic critical text
    evaluation = Evaluation(ip="2.3.4.5", risk=RiskLevel.LOW, critical_points=[])
    text = generate_management_text(BusinessRisk.CRITICAL, evaluation)
    assert "Gesamteinschätzung" in text
    assert "Risikoindikatoren" in text


def test_many_critical_points_are_listed():
    critical_points = [f"Problem {i}" for i in range(1, 21)]
    evaluation = Evaluation(
        ip="3.3.3.3", risk=RiskLevel.HIGH, critical_points=critical_points
    )
    text = generate_management_text(BusinessRisk.CRITICAL, evaluation)
    assert "Gesamteinschätzung" in text


def test_handles_empty_critical_points():
    evaluation = Evaluation(ip="10.10.10.10", risk=RiskLevel.HIGH, critical_points=[])
    text = generate_management_text(BusinessRisk.CRITICAL, evaluation)
    assert "Gesamteinschätzung" in text


def test_critical_points_are_expanded_with_technical_json():
    # Simuliere einen Snapshot mit einem SSH-Dienst
    critical_points = ["Kritischer Dienst gefunden: SSH auf Port 22"]
    evaluation = Evaluation(ip="5.6.7.8", risk=RiskLevel.HIGH, critical_points=critical_points)

    technical_json = {
        "services": [
            {
                "port": 22,
                "product": "OpenSSH",
                "version": "8.2p1",
                "banner": "OpenSSH_8.2p1",
                "cves": ["CVE-2020-14145"],
            }
        ]
    }

    text = generate_management_text(BusinessRisk.CRITICAL, evaluation, technical_json=technical_json)

    # SSH-Szenario: SSH-spezifischer Text wird erwartet
    assert "SSH" in text
    assert "Port 22" in text


# ── _text_rdp: TLS / EOL / CVE label changes ─────────────────────────────────

from shodan_report.reporting.management_text import _text_rdp  # noqa: E402


def test_text_rdp_tls_verified_sentence_present():
    """When insecure TLS protos are found, the VERIFIED sentence must appear."""
    text = _text_rdp(cve_count=0, port_count=1, tls_verified_protos={"TLSv1", "TLSv1.1"})
    assert "Verified Finding" in text
    assert "TLSv1" in text


def test_text_rdp_no_tls_no_verified_sentence():
    """Without TLS findings, no TLS sentence appears."""
    text = _text_rdp(cve_count=0, port_count=1)
    assert "Verified Finding" not in text


def test_text_rdp_cve_label_uses_inferred():
    """CVE note must say 'Inferred Findings', not 'OSINT-Indizien'."""
    text = _text_rdp(cve_count=5, port_count=1)
    assert "Inferred Findings" in text
    assert "OSINT-Indizien" not in text


def test_text_rdp_highest_risk_sentence_with_eol():
    """RDP + EOL combo sentence must mention 'nicht die Anzahl der CVEs'."""
    eol = [{"eol_status": "eol", "display_name": "Windows Server 2016"}]
    text = _text_rdp(cve_count=0, port_count=1, eol_findings=eol)
    assert "Das höchste Risiko ist nicht die Anzahl der CVEs" in text


def test_text_rdp_no_highest_risk_without_eol():
    """Without EOL findings, no 'Das höchste Risiko' sentence."""
    text = _text_rdp(cve_count=0, port_count=1, eol_findings=[])
    assert "Das höchste Risiko ergibt sich" not in text


def test_generate_management_text_rdp_with_tls_verified():
    """Full pipeline: RDP with insecure TLS in ssl_info.versions → Verified Finding in summary."""
    from shodan_report.evaluation.evaluation import Evaluation, RiskLevel
    evaluation = Evaluation(ip="1.2.3.4", risk=RiskLevel.HIGH, critical_points=[])
    technical_json = {
        "services": [
            {"port": 3389, "product": "ms-wbt-server", "ssl_info": {"versions": ["TLSv1", "-TLSv1.1"]}},
        ]
    }
    text = generate_management_text(BusinessRisk.CRITICAL, evaluation, technical_json=technical_json)
    assert "Verified Finding" in text
    assert "TLSv1" in text

