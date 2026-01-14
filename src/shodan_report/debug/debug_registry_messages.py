# debug_registry_messages.py
from shodan_report.models import Service
from shodan_report.evaluation.evaluators.registry import ServiceEvaluatorRegistry
from shodan_report.evaluation.config import EvaluationConfig

test_service = Service(
    port=3306,
    transport="tcp",
    product="MySQL",
    version="5.7.33",
    vulnerabilities=[{"id": "CVE-2023-12345", "cvss": 9.8}],
)

config = EvaluationConfig()
registry = ServiceEvaluatorRegistry(config)

risk = registry.evaluate_service(test_service)

print("=== TEST: Registry Message-Kombination ===")
print(f"Total risk score: {risk.risk_score}")
print(f"Message: {risk.message}")
print(f"Is critical: {risk.is_critical}")
print(f"Has critical_points attr: {hasattr(risk, 'critical_points')}")

if hasattr(risk, "critical_points"):
    print(f"Critical points: {risk.critical_points}")
    print(f"Number of critical points: {len(risk.critical_points)}")

    # Sollte enthalten:
    # 1. Datenbank-Warnung (DatabaseEvaluator)
    # 2. CVE-Warnung (CVEEvaluator)
    # 3. Version-Warnung (VersionEvaluator)
