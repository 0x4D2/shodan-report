"""Edge-Case-Tests für evaluation/helpers/cve_helpers.py."""
import pytest
from shodan_report.evaluation.helpers.cve_helpers import (
    CVE, CVESeverity,
    convert_to_cve_objects,
    count_cves_by_severity,
    generate_cve_message,
)


# ── CVE.severity / CVE.is_critical Grenzen ───────────────────────────────────

class TestCVESeverityBoundaries:
    @pytest.mark.parametrize("cvss,expected", [
        (9.0,  CVESeverity.CRITICAL),
        (8.9,  CVESeverity.HIGH),
        (7.0,  CVESeverity.HIGH),
        (6.9,  CVESeverity.MEDIUM),
        (4.0,  CVESeverity.MEDIUM),
        (3.9,  CVESeverity.LOW),
        (0.1,  CVESeverity.LOW),
        (0.0,  CVESeverity.NONE),
    ])
    def test_severity_at_boundary(self, cvss, expected):
        assert CVE("CVE-X", cvss).severity == expected

    @pytest.mark.parametrize("cvss,expected", [
        (7.0, True),
        (6.9, False),
        (9.9, True),
    ])
    def test_is_critical_boundary(self, cvss, expected):
        assert CVE("CVE-X", cvss).is_critical == expected


# ── convert_to_cve_objects Edge Cases ────────────────────────────────────────

class TestConvertToCveObjects:
    def test_cvss_none_in_dict(self):
        """cvss=None im Dict darf keinen crash verursachen."""
        cves = convert_to_cve_objects([{"id": "CVE-2024-1", "cvss": None}])
        assert len(cves) == 1
        assert cves[0].cvss == 0.0

    def test_cvss_non_numeric_string(self):
        """cvss='>9.0' oder 'critical' → Fallback 0.0."""
        for bad in [">9.0", "critical", "HIGH", "N/A", "--"]:
            cves = convert_to_cve_objects([{"id": "CVE-X", "cvss": bad}])
            assert cves[0].cvss == 0.0, f"cvss='{bad}' sollte 0.0 ergeben"

    def test_empty_list(self):
        assert convert_to_cve_objects([]) == []

    def test_dict_missing_id(self):
        """Fehlendes 'id'-Feld → UNKNOWN-CVE als Fallback."""
        cves = convert_to_cve_objects([{"cvss": 5.0}])
        assert cves[0].id == "UNKNOWN-CVE"

    def test_dict_missing_cvss_defaults_to_zero(self):
        cves = convert_to_cve_objects([{"id": "CVE-2024-99"}])
        assert cves[0].cvss == 0.0

    def test_severity_accessible_after_none_cvss(self):
        """Nach None-cvss-Fix muss .severity ohne TypeError aufrufbar sein."""
        cves = convert_to_cve_objects([{"id": "CVE-2024-1", "cvss": None}])
        _ = cves[0].severity  # darf keinen TypeError werfen

    def test_string_entry_gets_zero_cvss(self):
        cves = convert_to_cve_objects(["CVE-2024-STRING"])
        assert cves[0].cvss == 0.0
        assert cves[0].severity == CVESeverity.NONE

    def test_mixed_types(self):
        raw = [
            {"id": "CVE-A", "cvss": 9.5},
            "CVE-B",
            {"id": "CVE-C", "cvss": None},
        ]
        cves = convert_to_cve_objects(raw)
        assert len(cves) == 3


# ── count_cves_by_severity Edge Cases ────────────────────────────────────────

class TestCountCvesBySeverity:
    def test_empty_list(self):
        counts = count_cves_by_severity([])
        assert counts["total"] == 0
        assert counts["critical"] == 0

    def test_all_severities(self):
        cves = [CVE("a", 9.5), CVE("b", 7.5), CVE("c", 5.0), CVE("d", 2.0), CVE("e", 0.0)]
        counts = count_cves_by_severity(cves)
        assert counts == {"critical": 1, "high": 1, "medium": 1, "low": 1, "total": 5}

    def test_zero_cvss_not_counted_in_low(self):
        counts = count_cves_by_severity([CVE("x", 0.0)])
        assert counts["low"] == 0
        assert counts["total"] == 1


# ── generate_cve_message Edge Cases ──────────────────────────────────────────

class TestGenerateCveMessage:
    def test_service_none(self):
        """service=None darf keinen AttributeError werfen."""
        counts = {"critical": 1, "total": 1}
        msg = generate_cve_message(counts, None)
        assert "kritische" in msg

    def test_service_product_none(self):
        class S:
            product = None
            version = None
        msg = generate_cve_message({"high": 1, "total": 1}, S())
        assert "hochriskante" in msg
        assert "()" not in msg

    def test_service_version_none(self):
        class S:
            product = "nginx"
            version = None
        msg = generate_cve_message({"critical": 2, "total": 2}, S())
        assert "nginx" in msg
        assert "None" not in msg

    def test_total_zero_returns_empty(self):
        assert generate_cve_message({"total": 0}, None) == ""

    def test_only_medium_cves(self):
        counts = {"critical": 0, "high": 0, "medium": 3, "total": 3}

        class S:
            product = "apache"
            version = "2.4"
        msg = generate_cve_message(counts, S())
        assert "3" in msg
        assert "apache" in msg
