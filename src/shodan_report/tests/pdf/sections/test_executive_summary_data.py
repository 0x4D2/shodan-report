from shodan_report.pdf.sections.data.executive_summary_data import (
    collect_positive_points,
    prepare_executive_summary_data,
    risk_status,
)


class FakeCtx:
    business_risk = "medium"
    management_text = "Management summary"
    technical_json = {
        "open_ports": [
            {"port": 443, "product": "nginx", "tls": {"cert_expiry": "20260723175119Z"}, "ssl_info": {"versions": ["TLSv1.2"]}},
        ],
        "cve_enriched": [],
    }
    evaluation = {"cves": [{"id": "CVE-2024-0001", "cvss": 9.0}]}
    config = {"report": {"cover_note": "Executive note"}}
    greynoise = {"available": True, "classification": "benign", "noise": False}


def test_risk_status_mapping():
    assert risk_status("critical") == "action_required"
    assert risk_status("medium") == "watch"
    assert risk_status("low") == "stable"


def test_collect_positive_points_prefers_observable_good_signals():
    points = collect_positive_points(FakeCtx.technical_json, FakeCtx.greynoise)
    assert any("TLS" in point for point in points)
    assert any("GreyNoise" in point for point in points)


def test_prepare_executive_summary_data_uses_cover_note_and_action_groups():
    data = prepare_executive_summary_data(FakeCtx())
    assert data["summary_text"] == "Executive note"
    assert data["status_key"] == "watch"
    assert any(group[0] == "Sofort" for group in data["recommendation_groups"])