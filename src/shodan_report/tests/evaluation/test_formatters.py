"""Tests für evaluation/formatters.py — prioritize_risk und technical_to_business_risk."""
import pytest
from shodan_report.evaluation.core import RiskLevel, BusinessRisk, Evaluation
from shodan_report.evaluation.formatters import prioritize_risk, technical_to_business_risk


class _Eval:
    """Minimales Evaluation-Stub ohne AssetSnapshot."""
    def __init__(self, risk: RiskLevel, critical_points=None):
        self.risk = risk
        self.critical_points = critical_points or []


# ── prioritize_risk ───────────────────────────────────────────────────────────

class TestPrioritizeRisk:
    def test_critical_risk_maps_to_critical(self):
        assert prioritize_risk(_Eval(RiskLevel.CRITICAL)) == BusinessRisk.CRITICAL

    def test_high_risk_maps_to_critical(self):
        assert prioritize_risk(_Eval(RiskLevel.HIGH)) == BusinessRisk.CRITICAL

    def test_medium_risk_maps_to_attention(self):
        assert prioritize_risk(_Eval(RiskLevel.MEDIUM)) == BusinessRisk.ATTENTION

    def test_low_risk_maps_to_monitor(self):
        assert prioritize_risk(_Eval(RiskLevel.LOW)) == BusinessRisk.MONITOR

    def test_low_risk_with_critical_point_keyword_escalates(self):
        """LOW + 'Kritischer Dienst gefunden' im critical_point → CRITICAL."""
        ev = _Eval(RiskLevel.LOW, ["Kritischer Dienst gefunden: RDP"])
        assert prioritize_risk(ev) == BusinessRisk.CRITICAL

    def test_medium_risk_with_unrelated_critical_point_stays_attention(self):
        """MEDIUM + critical_point ohne Schlüsselwort → ATTENTION (kein Upgrade)."""
        ev = _Eval(RiskLevel.MEDIUM, ["Viele offene Ports"])
        assert prioritize_risk(ev) == BusinessRisk.ATTENTION

    def test_empty_critical_points_low_is_monitor(self):
        ev = _Eval(RiskLevel.LOW, [])
        assert prioritize_risk(ev) == BusinessRisk.MONITOR

    def test_multiple_critical_points_one_matches(self):
        """Nur einer der Punkte enthält das Schlüsselwort — muss trotzdem eskalieren."""
        ev = _Eval(RiskLevel.LOW, ["Viele Ports", "Kritischer Dienst gefunden: Telnet", "HTTP ohne TLS"])
        assert prioritize_risk(ev) == BusinessRisk.CRITICAL

    def test_critical_point_keyword_substring_match(self):
        """Schlüsselwort muss als Substring matchen, nicht exakt."""
        ev = _Eval(RiskLevel.LOW, ["[!] Kritischer Dienst gefunden (Port 23)"])
        assert prioritize_risk(ev) == BusinessRisk.CRITICAL


# ── technical_to_business_risk ────────────────────────────────────────────────

class TestTechnicalToBusinessRisk:
    @pytest.mark.parametrize("risk,expected", [
        (RiskLevel.CRITICAL, BusinessRisk.CRITICAL),
        (RiskLevel.HIGH,     BusinessRisk.CRITICAL),
        (RiskLevel.MEDIUM,   BusinessRisk.ATTENTION),
        (RiskLevel.LOW,      BusinessRisk.MONITOR),
    ])
    def test_mapping(self, risk, expected):
        assert technical_to_business_risk(risk) == expected

    def test_default_critical_points_is_empty_list(self):
        """Kein critical_points-Argument → kein Fehler."""
        result = technical_to_business_risk(RiskLevel.LOW)
        assert result == BusinessRisk.MONITOR

    def test_explicit_empty_critical_points(self):
        result = technical_to_business_risk(RiskLevel.MEDIUM, critical_points=[])
        assert result == BusinessRisk.ATTENTION

    def test_critical_points_ignored_in_technical_to_business(self):
        """technical_to_business_risk ignoriert critical_points — nur RiskLevel zählt."""
        result = technical_to_business_risk(RiskLevel.LOW, critical_points=["Kritischer Dienst gefunden"])
        assert result == BusinessRisk.MONITOR
