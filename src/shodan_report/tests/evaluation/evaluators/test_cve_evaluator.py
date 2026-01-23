# tests/evaluation/evaluators/test_cve_evaluator.py
import pytest
from unittest.mock import Mock
from shodan_report.models import Service
from shodan_report.evaluation.config import EvaluationConfig
from shodan_report.evaluation.evaluators.cve_evaluator import (
    CVEEvaluator,
    CVE,
    CVESeverity,
)


class TestCVEEvaluator:
    """Test-Klasse für CVEEvaluator."""

    @pytest.fixture
    def config(self):
        """Erstellt eine EvaluationConfig für Tests."""
        return EvaluationConfig()

    @pytest.fixture
    def evaluator(self, config):
        """Erstellt einen CVEEvaluator für Tests."""
        return CVEEvaluator(config)

    @pytest.fixture
    def service_without_cves(self):
        """Service ohne CVEs."""
        return Service(
            port=80,
            transport="tcp",
            product="nginx",
            version="1.18.0",
            vulnerabilities=[],
        )

    @pytest.fixture
    def service_with_cves(self):
        """Service mit verschiedenen CVEs."""
        return Service(
            port=3306,
            transport="tcp",
            product="MySQL",
            version="8.0.33",
            vulnerabilities=[
                {"id": "CVE-2023-12345", "cvss": 9.8, "summary": "Critical RCE"},
                {"id": "CVE-2023-56789", "cvss": 8.5, "summary": "High severity flaw"},
                {"id": "CVE-2023-11111", "cvss": 7.2, "summary": "Medium issue"},
                {"id": "CVE-2023-22222", "cvss": 6.5, "summary": "Another issue"},
                {"id": "CVE-2023-33333", "cvss": 5.0, "summary": "Low issue"},
            ],
        )

    @pytest.fixture
    def service_with_many_cves(self):
        """Service mit vielen CVEs (wie MySQL 8.0.33 in Realität)."""
        cves = []
        for i in range(88):  # 88 CVEs wie im echten Beispiel
            cve_id = f"CVE-2023-{10000 + i}"
            cvss = (
                9.8 if i < 12 else (8.0 if i < 30 else 6.0)
            )  # 12 kritisch, 18 hoch, rest mittel
            cves.append({"id": cve_id, "cvss": cvss})

        return Service(
            port=3306,
            transport="tcp",
            product="MySQL",
            version="8.0.33",
            vulnerabilities=cves,
        )

    @pytest.fixture
    def service_with_critical_only(self):
        """Service nur mit kritischen CVEs."""
        return Service(
            port=443,
            transport="tcp",
            product="Apache",
            version="2.4.49",
            vulnerabilities=[
                {"id": "CVE-2021-41773", "cvss": 9.8},
                {"id": "CVE-2021-42013", "cvss": 9.8},
            ],
        )

    # TEST 1: applies_to()
    def test_applies_to_with_cves(self, evaluator, service_with_cves):
        """Testet ob Evaluator auf Service mit CVEs zutrifft."""
        assert evaluator.applies_to(service_with_cves) == True

    def test_applies_to_without_cves(self, evaluator, service_without_cves):
        """Testet ob Evaluator auf Service ohne CVEs zutrifft."""
        assert evaluator.applies_to(service_without_cves) == False

    # TEST 2: evaluate() - Keine CVEs
    def test_evaluate_without_cves(self, evaluator, service_without_cves):
        """Testet Evaluation von Service ohne CVEs."""
        risk = evaluator.evaluate(service_without_cves)

        assert risk.risk_score == 0
        assert risk.message is None or risk.message == ""
        assert risk.is_critical == False
        assert risk.recommendations == []

    # TEST 3: evaluate() - Mit verschiedenen CVEs
    def test_evaluate_with_mixed_cves(self, evaluator, service_with_cves):
        """Testet Evaluation von Service mit gemischten CVEs."""
        risk = evaluator.evaluate(service_with_cves)

        # Erwartet: 1 kritisch (9.8), 1 hoch (8.5), 1 hoch (7.2) = Risiko 4
        assert risk.risk_score == 4  # Weil 1 kritischer CVE
        assert "kritische CVEs" in risk.message or "CVEs identifiziert" in risk.message
        assert risk.is_critical == True  # Weil kritische CVEs vorhanden
        assert len(risk.recommendations) > 0

    # TEST 4: evaluate() - Viele CVEs (MySQL 8.0.33 Szenario)
    def test_evaluate_with_many_cves(self, evaluator, service_with_many_cves):
        """Testet Evaluation von Service mit vielen CVEs."""
        risk = evaluator.evaluate(service_with_many_cves)

        # 12 kritische + viele hohe CVEs = Maximales Risiko
        assert risk.risk_score == 5  # Maximaler Score
        assert "kritische CVEs" in risk.message
        assert risk.is_critical == True
        assert "Kritische CVEs umgehend patchen" in risk.recommendations

    # TEST 5: evaluate() - Nur kritische CVEs
    def test_evaluate_critical_only(self, evaluator, service_with_critical_only):
        """Testet Evaluation von Service nur mit kritischen CVEs."""
        risk = evaluator.evaluate(service_with_critical_only)

        assert risk.risk_score >= 4  # Mindestens 4 wegen kritischer CVEs
        assert risk.is_critical == True
        assert any("kritisch" in rec.lower() for rec in risk.recommendations)

    # TEST 6: Risiko-Score Logik
    def test_risk_score_calculation(self, evaluator):
        """Testet die Risiko-Score-Berechnung direkt."""
        test_cases = [
            # (kritische_cves, hohe_cves, totale_cves, erwarteter_score)
            (0, 0, 0, 0),  # Keine CVEs
            (0, 0, 1, 1),  # 1 CVE, nicht kritisch/hoch
            (0, 0, 5, 2),  # 5 CVEs
            (0, 0, 10, 3),  # 10 CVEs
            (0, 2, 2, 4),  # 2 hohe CVEs
            (1, 0, 1, 4),  # 1 kritischer CVE
            (3, 0, 3, 5),  # 3 kritische CVEs
            (1, 2, 3, 4),  # 1 kritisch + 2 hoch
        ]

        for critical, high, total, expected_score in test_cases:
            # Erstelle Mock-CVEs
            cves = []
            for i in range(critical):
                cves.append(CVE(id=f"CVE-TEST-CRIT-{i}", cvss=9.8))
            for i in range(high):
                cves.append(CVE(id=f"CVE-TEST-HIGH-{i}", cvss=8.0))
            for i in range(total - critical - high):
                cves.append(CVE(id=f"CVE-TEST-LOW-{i}", cvss=5.0))

            score = evaluator._calculate_cve_risk_score(cves)
            assert (
                score == expected_score
            ), f"Failed for: critical={critical}, high={high}, total={total}"

    # TEST 7: CVE-Konvertierung
    def test_convert_to_cve_objects(self, evaluator):
        """Testet Konvertierung von Raw-CVE-Daten zu CVE-Objekten."""
        raw_vulnerabilities = [
            {"id": "CVE-2023-12345", "cvss": 9.8},
            {"id": "CVE-2023-56789", "cvss": "8.5"},  # String CVSS
            "CVE-2023-99999",  # Nur String-ID
            {"id": "CVE-2023-11111", "cvss": None},  # Kein CVSS
            {"id": "CVE-2023-22222"},  # Ohne cvss Feld
        ]

        cves = evaluator._convert_to_cve_objects(raw_vulnerabilities)

        assert len(cves) == 5
        assert cves[0].id == "CVE-2023-12345"
        assert cves[0].cvss == 9.8
        assert cves[1].cvss == 8.5  # String sollte zu float konvertiert werden
        assert cves[2].id == "CVE-2023-99999"
        assert cves[2].cvss == 0.0  # Default für String-ID

    # TEST 8: CVE-Zählung nach Schweregrad
    def test_count_cves_by_severity(self, evaluator):
        """Testet Zählung von CVEs nach Schweregrad."""
        cves = [
            CVE(id="CVE-1", cvss=9.8),  # kritisch
            CVE(id="CVE-2", cvss=9.0),  # kritisch
            CVE(id="CVE-3", cvss=8.5),  # hoch
            CVE(id="CVE-4", cvss=7.0),  # hoch
            CVE(id="CVE-5", cvss=6.5),  # mittel
            CVE(id="CVE-6", cvss=4.0),  # mittel
            CVE(id="CVE-7", cvss=3.0),  # niedrig
            CVE(id="CVE-8", cvss=0.0),  # none (wird nicht gezählt)
        ]

        counts = evaluator._count_cves_by_severity(cves)

        assert counts["critical"] == 2
        assert counts["high"] == 2
        assert counts["medium"] == 2
        assert counts["low"] == 1
        assert counts["total"] == 8

    # TEST 9: Message-Generierung
    def test_generate_cve_message(self, evaluator):
        """Testet Generierung von CVE-Messages."""
        service = Service(port=80, transport="tcp", product="nginx", version="1.18.0")

        test_cases = [
            # (counts dict, expected_message_fragment)
            ({"critical": 2, "high": 3, "total": 5}, "kritische CVEs"),
            ({"critical": 0, "high": 3, "total": 3}, "hochriskante CVEs"),
            ({"critical": 0, "high": 0, "total": 5}, "CVEs identifiziert"),
            ({"critical": 0, "high": 0, "total": 0}, ""),
        ]

        for counts, expected in test_cases:
            message = evaluator._generate_cve_message(counts, service)
            if expected:
                assert expected in message
            else:
                assert message == ""

    # TEST 10: Empfehlungs-Generierung
    def test_generate_recommendations(self, evaluator):
        """Testet Generierung von Empfehlungen."""
        top_cves = [CVE(id="CVE-2023-12345", cvss=9.8)]

        test_cases = [
            # (counts dict, expected_recommendation_fragment)
            ({"critical": 1, "high": 0, "total": 1}, "Kritische CVEs umgehend patchen"),
            (
                {"critical": 0, "high": 3, "total": 3},
                "Hochriskante CVEs prioritär behandeln",
            ),
            ({"critical": 0, "high": 0, "total": 10}, "Sicherheitsupdates durchführen"),
        ]

        for counts, expected in test_cases:
            recs = evaluator._generate_recommendations(counts, top_cves)
            assert any(expected in rec for rec in recs)

    # TEST 11: CVE Dataclass Properties
    def test_cve_dataclass_properties(self):
        """Testet die CVE Dataclass Properties."""
        # Test severity property
        test_cases = [
            (9.8, CVESeverity.CRITICAL),
            (8.5, CVESeverity.HIGH),
            (6.5, CVESeverity.MEDIUM),
            (3.5, CVESeverity.LOW),
            (0.0, CVESeverity.NONE),
        ]

        for cvss, expected_severity in test_cases:
            cve = CVE(id="TEST", cvss=cvss)
            assert cve.severity == expected_severity

        # Test is_critical property
        cve_critical = CVE(id="TEST", cvss=7.0)
        cve_not_critical = CVE(id="TEST", cvss=6.9)

        assert cve_critical.is_critical == True
        assert cve_not_critical.is_critical == False


# Integrationstest mit Registry
class TestCVEEvaluatorIntegration:
    """Integrationstests für CVEEvaluator mit Registry."""

    @pytest.fixture
    def registry(self):
        """Erstellt eine Registry mit CVEEvaluator."""
        from shodan_report.evaluation.evaluators.registry import (
            ServiceEvaluatorRegistry,
        )
        from shodan_report.evaluation.config import EvaluationConfig

        config = EvaluationConfig()
        return ServiceEvaluatorRegistry(config)

    def test_cve_evaluator_in_registry(self, registry):
        """Testet ob CVEEvaluator in der Registry ist und funktioniert."""
        # Überprüfe ob ein CVEEvaluator in der Registry ist
        evaluator_names = [type(e).__name__ for e in registry.evaluators]
        assert "CVEEvaluator" in evaluator_names

        # Test-Service mit CVEs
        service = Service(
            port=3306,
            transport="tcp",
            product="MySQL",
            version="8.0.33",
            vulnerabilities=[{"id": "CVE-2023-12345", "cvss": 9.8}],
        )

        # Evaluierung sollte CVEEvaluator verwenden
        risk = registry.evaluate_service(service)

        # Da auch DatabaseEvaluator zutrifft, sollte Risiko erhöht sein
        assert risk.risk_score > 0
        assert risk.message is not None


if __name__ == "__main__":
    # Zum manuellen Ausführen der Tests
    pytest.main([__file__, "-v"])
