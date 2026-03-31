# tests/reporting/test_report_validator.py
# ─────────────────────────────────────────────────────────────────────────────
# Report Logic Test Suite — prüft Konsistenz zwischen Score, Findings und Text.
#
# Jeder Test deckt einen konkreten Widerspruch ab, der in der Produktion
# aufgetreten ist oder auftreten kann.
# ─────────────────────────────────────────────────────────────────────────────

import pytest
from shodan_report.reporting.report_validator import validate_report, ReportViolation


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _violation_rules(violations) -> set:
    return {v.rule for v in violations}


def _make_tls_service(port: int = 443, insecure_version: str = "TLSv1") -> dict:
    return {
        "port": port,
        "product": "nginx",
        "ssl_info": {"versions": [insecure_version, "-SSLv2", "TLSv1.2"]},
    }


def _make_rdp_service() -> dict:
    return {"port": 3389, "product": "Microsoft Terminal Services"}


def _make_cve_service(port: int = 80, cve_id: str = "CVE-2023-1234") -> dict:
    return {"port": port, "product": "Apache", "vulnerabilities": [{"id": cve_id, "cvss": 7.5}]}


# ──────────────────────────────────────────────────────────────────────────────
# 1. Score ↔ Text Konsistenz
# ──────────────────────────────────────────────────────────────────────────────

class TestStabilityScoreMismatch:
    def test_score_3_with_stable_text_is_invalid(self):
        """Score 3/5 + 'stabil' im Text → STABILITY_SCORE_MISMATCH."""
        violations = validate_report(
            exposure_score=3,
            text="Die externe Sicherheitslage ist stabil. Kein Handlungsbedarf.",
            technical_json={},
        )
        assert "STABILITY_SCORE_MISMATCH" in _violation_rules(violations)

    def test_score_4_with_kein_handlungsbedarf_is_invalid(self):
        """Score 4/5 + 'kein Handlungsbedarf' → STABILITY_SCORE_MISMATCH."""
        violations = validate_report(
            exposure_score=4,
            text="Kein unmittelbarer Handlungsbedarf. Monatliche Wiederholung empfohlen.",
            technical_json={},
        )
        assert "STABILITY_SCORE_MISMATCH" in _violation_rules(violations)

    def test_score_2_with_stable_text_is_valid(self):
        """Score 2/5 + 'stabil' → kein Fehler."""
        violations = validate_report(
            exposure_score=2,
            text="Die externe Sicherheitslage ist stabil. Kein Handlungsbedarf.",
            technical_json={},
        )
        assert "STABILITY_SCORE_MISMATCH" not in _violation_rules(violations)

    def test_score_3_with_elevated_text_is_valid(self):
        """Score 3/5 + 'erhöht' → kein Fehler."""
        violations = validate_report(
            exposure_score=3,
            text="Die externe Sicherheitslage ist erhöht. Konfigurationsrisiken identifiziert.",
            technical_json={},
        )
        assert "STABILITY_SCORE_MISMATCH" not in _violation_rules(violations)


class TestCriticalScoreSoftText:
    def test_score_4_without_urgency_is_invalid(self):
        """Score 4/5 aber kein Urgenz-Signal → CRITICAL_SCORE_SOFT_TEXT."""
        violations = validate_report(
            exposure_score=4,
            text="Es wurden einige Dienste identifiziert. Überprüfung empfohlen.",
            technical_json={},
        )
        assert "CRITICAL_SCORE_SOFT_TEXT" in _violation_rules(violations)

    def test_score_4_with_kritisch_text_is_valid(self):
        """Score 4/5 + 'kritisch' im Text → kein Fehler."""
        violations = validate_report(
            exposure_score=4,
            text="Bewertung: KRITISCH EXPONIERT — sofortiger Handlungsbedarf.",
            technical_json={},
        )
        assert "CRITICAL_SCORE_SOFT_TEXT" not in _violation_rules(violations)

    def test_score_5_requires_urgency(self):
        """Score 5/5 ohne Dringlichkeit → CRITICAL_SCORE_SOFT_TEXT."""
        violations = validate_report(
            exposure_score=5,
            text="Mehrere öffentliche Dienste gefunden.",
            technical_json={},
        )
        assert "CRITICAL_SCORE_SOFT_TEXT" in _violation_rules(violations)


# ──────────────────────────────────────────────────────────────────────────────
# 2. RDP Regeln
# ──────────────────────────────────────────────────────────────────────────────

class TestRDPRules:
    def test_rdp_with_low_score_is_invalid(self):
        """RDP exponiert + Score < 4 → RDP_SCORE_MISMATCH."""
        violations = validate_report(
            exposure_score=2,
            text="RDP ist erreichbar.",
            technical_json={"open_ports": [_make_rdp_service()]},
        )
        assert "RDP_SCORE_MISMATCH" in _violation_rules(violations)

    def test_rdp_with_score_4_no_mismatch(self):
        """RDP exponiert + Score 4 → kein RDP_SCORE_MISMATCH."""
        violations = validate_report(
            exposure_score=4,
            text="Bewertung: KRITISCH. VPN oder Jumphost einrichten.",
            technical_json={"open_ports": [_make_rdp_service()]},
        )
        assert "RDP_SCORE_MISMATCH" not in _violation_rules(violations)

    def test_rdp_without_remediation_in_text_is_invalid(self):
        """RDP exponiert aber kein VPN/Jumphost/NLA im Text → RDP_MISSING_REMEDIATION."""
        violations = validate_report(
            exposure_score=4,
            text="Bewertung: KRITISCH EXPONIERT. Weitere Analyse notwendig.",
            technical_json={"open_ports": [_make_rdp_service()]},
        )
        assert "RDP_MISSING_REMEDIATION" in _violation_rules(violations)

    def test_rdp_with_vpn_in_text_is_valid(self):
        """RDP exponiert + VPN im Text → RDP_MISSING_REMEDIATION nicht ausgelöst."""
        violations = validate_report(
            exposure_score=4,
            text="Bewertung: KRITISCH. RDP hinter VPN absichern oder Jumphost einrichten.",
            technical_json={"open_ports": [_make_rdp_service()]},
        )
        assert "RDP_MISSING_REMEDIATION" not in _violation_rules(violations)

    def test_no_rdp_no_rdp_rules_triggered(self):
        """Kein RDP → keine RDP-Regeln ausgelöst."""
        violations = validate_report(
            exposure_score=2,
            text="Die Sicherheitslage ist stabil.",
            technical_json={"open_ports": [{"port": 80, "product": "nginx"}]},
        )
        rdp_rules = {"RDP_SCORE_MISMATCH", "RDP_MISSING_REMEDIATION"}
        assert not rdp_rules & _violation_rules(violations)


# ──────────────────────────────────────────────────────────────────────────────
# 3. EOL Regeln
# ──────────────────────────────────────────────────────────────────────────────

class TestEOLRules:
    def test_eol_with_score_below_3_invalid(self):
        """
        EOL erkannt + Score < 3 → EOL_UNDERSCORING.
        Simuliert via Mock, da EOL-Scan externe Daten braucht.
        """
        from unittest.mock import patch
        with patch(
            "shodan_report.reporting.report_validator._has_eol", return_value=True
        ):
            violations = validate_report(
                exposure_score=2,
                text="Sicherheitslage stabil.",
                technical_json={"open_ports": [{"port": 80, "product": "nginx"}]},
            )
        assert "EOL_UNDERSCORING" in _violation_rules(violations)

    def test_eol_with_score_3_no_underscoring(self):
        """EOL erkannt + Score 3 → kein EOL_UNDERSCORING."""
        from unittest.mock import patch
        with patch(
            "shodan_report.reporting.report_validator._has_eol", return_value=True
        ):
            violations = validate_report(
                exposure_score=3,
                text="Sicherheitslage erhöht. EOL-Software identifiziert.",
                technical_json={"open_ports": [{"port": 80}]},
            )
        assert "EOL_UNDERSCORING" not in _violation_rules(violations)


# ──────────────────────────────────────────────────────────────────────────────
# 4. TLS Regeln
# ──────────────────────────────────────────────────────────────────────────────

class TestTLSRules:
    def test_insecure_tls_with_score_below_3_invalid(self):
        """TLS 1.0 aktiv + Score < 3 → TLS_UNDERSCORING."""
        violations = validate_report(
            exposure_score=2,
            text="Sicherheitslage stabil.",
            technical_json={"open_ports": [_make_tls_service()]},
        )
        assert "TLS_UNDERSCORING" in _violation_rules(violations)

    def test_insecure_tls_with_score_3_no_underscoring(self):
        """TLS 1.0 aktiv + Score 3 → kein TLS_UNDERSCORING."""
        violations = validate_report(
            exposure_score=3,
            text="Sicherheitslage erhöht. TLS 1.0 aktiv.",
            technical_json={"open_ports": [_make_tls_service()]},
        )
        assert "TLS_UNDERSCORING" not in _violation_rules(violations)

    def test_tls_text_contradiction(self):
        """TLS-Probleme + 'keine Konfigurationsrisiken' im Text → TLS_TEXT_CONTRADICTION."""
        violations = validate_report(
            exposure_score=3,
            text="Keine Konfigurationsrisiken erkannt. TLS läuft.",
            technical_json={"open_ports": [_make_tls_service()]},
        )
        assert "TLS_TEXT_CONTRADICTION" in _violation_rules(violations)

    def test_tls12_only_no_violation(self):
        """Nur TLS 1.2 → keine TLS-Verstöße."""
        violations = validate_report(
            exposure_score=2,
            text="Sicherheitslage stabil.",
            technical_json={"open_ports": [
                {"port": 443, "ssl_info": {"versions": ["TLSv1.2", "TLSv1.3", "-SSLv2"]}}
            ]},
        )
        tls_rules = {"TLS_UNDERSCORING", "TLS_TEXT_CONTRADICTION"}
        assert not tls_rules & _violation_rules(violations)


# ──────────────────────────────────────────────────────────────────────────────
# 5. CVE Regeln
# ──────────────────────────────────────────────────────────────────────────────

class TestCVERules:
    def test_cves_with_no_critical_claim_invalid(self):
        """CVEs vorhanden + Text behauptet 'keine kritischen Schwachstellen' → CVE_WITH_NEGATIVE_CLAIM."""
        violations = validate_report(
            exposure_score=3,
            text="Keine kritischen Schwachstellen wurden identifiziert.",
            technical_json={"open_ports": [_make_cve_service()]},
        )
        assert "CVE_WITH_NEGATIVE_CLAIM" in _violation_rules(violations)

    def test_cves_with_honest_text_valid(self):
        """CVEs vorhanden + ehrlicher Text → kein CVE_WITH_NEGATIVE_CLAIM."""
        violations = validate_report(
            exposure_score=3,
            text="Es wurden 1 CVE-Indikatoren identifiziert. Weitere Prüfung empfohlen.",
            technical_json={"open_ports": [_make_cve_service()]},
        )
        assert "CVE_WITH_NEGATIVE_CLAIM" not in _violation_rules(violations)

    def test_no_cves_no_cve_violations(self):
        """Keine CVEs → kein CVE_WITH_NEGATIVE_CLAIM."""
        violations = validate_report(
            exposure_score=2,
            text="Keine kritischen Schwachstellen wurden identifiziert.",
            technical_json={"open_ports": [{"port": 80, "product": "nginx"}]},
        )
        assert "CVE_WITH_NEGATIVE_CLAIM" not in _violation_rules(violations)


# ──────────────────────────────────────────────────────────────────────────────
# 6. Clean Report — darf keine Violations erzeugen
# ──────────────────────────────────────────────────────────────────────────────

class TestCleanReport:
    def test_low_score_clean_report_zero_violations(self):
        """Stabiler Bericht mit Score 2/5 → null Violations."""
        violations = validate_report(
            exposure_score=2,
            text="Die externe Sicherheitslage ist stabil. Kein unmittelbarer Handlungsbedarf.",
            technical_json={"open_ports": [{"port": 80, "product": "nginx"}]},
        )
        assert violations == []

    def test_elevated_report_correct_text_zero_violations(self):
        """Score 3/5 + erhöhter Text + TLS-Findings → null Violations."""
        violations = validate_report(
            exposure_score=3,
            text=(
                "Die externe Sicherheitslage ist erhöht (Exposure-Level 3/5). "
                "Risikofaktoren: veraltete TLS-Protokolle (TLS 1.0/1.1) aktiv. "
                "Identifizierte Risikofaktoren innerhalb von 30 Tagen adressieren: "
                "TLS-Konfiguration härten (TLS 1.2+)."
            ),
            technical_json={"open_ports": [_make_tls_service()]},
        )
        assert violations == []

    def test_critical_rdp_report_correct_zero_violations(self):
        """Score 4/5 + RDP + VPN-Empfehlung + kritischer Text → null Violations."""
        violations = validate_report(
            exposure_score=4,
            text=(
                "Bewertung: KRITISCH EXPONIERT — sofortiger Handlungsbedarf. "
                "RDP hinter VPN absichern oder Jumphost einrichten. NLA aktivieren."
            ),
            technical_json={"open_ports": [_make_rdp_service()]},
        )
        assert violations == []


# ──────────────────────────────────────────────────────────────────────────────
# 7. ReportViolation Objekt
# ──────────────────────────────────────────────────────────────────────────────

class TestReportViolationObject:
    def test_violation_str_contains_rule_and_severity(self):
        v = ReportViolation(rule="TEST_RULE", message="test msg", severity="ERROR")
        assert "ERROR" in str(v)
        assert "TEST_RULE" in str(v)

    def test_validate_returns_list(self):
        result = validate_report(1, "stabil", {})
        assert isinstance(result, list)
