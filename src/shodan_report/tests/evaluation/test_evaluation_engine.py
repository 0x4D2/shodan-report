# src/shodan_report/tests/evaluation/test_evaluation_engine.py
import pytest
from dataclasses import dataclass
from shodan_report.evaluation.evaluators.registry import ServiceEvaluatorRegistry
from shodan_report.evaluation.evaluation_engine import EvaluationEngine
from shodan_report.evaluation.models import EvaluationResult, ServiceRisk
from shodan_report.models import AssetSnapshot, Service
from shodan_report.evaluation.risk_level import RiskLevel

# Dummy Config für Tests
@dataclass
class DummyWeights:
    high_risk_services: dict
    secure_indicators: list
    vulnerable_indicators: dict

@dataclass
class DummyConfig:
    weights: DummyWeights

def make_dummy_config():
    return DummyConfig(
        weights=DummyWeights(
            high_risk_services={
                "rdp_unencrypted": 100,
                "vnc_unencrypted": 100,
                "telnet": 100
            },
            secure_indicators=["ssl", "https"],
            vulnerable_indicators={"old": 5}
        )
    )

# Test Engine mit Dummy-Config
class TestEvaluationEngine(EvaluationEngine):
    def setup_method(self):
        config = make_dummy_config()
        self.registry = ServiceEvaluatorRegistry(config=config)

    def evaluate(self, snapshot: AssetSnapshot) -> EvaluationResult:
        critical_points = []
        insecure_count = 0

        for service in snapshot.services:
            risk: ServiceRisk = self.registry.evaluate_service(service)
            if risk.is_critical:
                critical_points.append(risk.message)
                insecure_count += 1

        return EvaluationResult(
            ip=snapshot.ip,
            risk=RiskLevel.HIGH if insecure_count > 0 else RiskLevel.LOW,
            exposure_score=insecure_count,
            critical_points=critical_points,
            recommendations=[],
            total_services=len(snapshot.services),
            insecure_services=insecure_count
        )

# Beispiel-Test
def test_evaluation_engine_critical_and_exposure():
    snapshot = AssetSnapshot(
        ip="1.2.3.4",
        hostnames=[],
        domains=[],
        org="TestOrg",
        isp="TestISP",
        os="Linux",
        city="Berlin",
        country="Germany",
        services=[
            Service(port=3389, transport="tcp", product="RDP"),
            Service(port=22, transport="tcp", product="OpenSSH", ssl_info={"cert": "dummy"}),
            Service(port=23, transport="tcp", product="Telnet")
        ],
        last_update=None,
        open_ports=[22, 23, 3389]
    )

    engine = TestEvaluationEngine()
    result: EvaluationResult = engine.evaluate(snapshot)

    assert result.insecure_services == 2  # RDP + Telnet sind kritisch
    assert "RDP öffentlich erreichbar ohne Verschlüsselung" in " ".join(result.critical_points)
    assert "Telnet (unverschlüsselt)" in " ".join(result.critical_points)
    assert result.total_services == 3
    assert result.risk == RiskLevel.HIGH
