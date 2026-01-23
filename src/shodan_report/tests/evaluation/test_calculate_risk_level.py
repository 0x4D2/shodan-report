from shodan_report.evaluation.core import _calculate_risk_level, RiskLevel


def test_calculate_risk_level_detects_critical():
    pts = ["RDP öffentlich erreichbar", "sonstiges"]
    assert _calculate_risk_level(pts, 0) == RiskLevel.CRITICAL


def test_calculate_risk_level_by_score():
    # Align with `evaluate_snapshot`'s thresholds: >=3 -> HIGH, >=1 -> MEDIUM
    assert _calculate_risk_level([], 4) == RiskLevel.HIGH
    assert _calculate_risk_level([], 3) == RiskLevel.HIGH
    assert _calculate_risk_level([], 0) == RiskLevel.LOW


def test_calculate_risk_level_case_insensitive():
    assert _calculate_risk_level(["telnet offen"], 0) == RiskLevel.CRITICAL
