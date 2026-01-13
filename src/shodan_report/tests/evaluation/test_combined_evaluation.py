# test_combined_evaluation.py
from shodan_report.models import Service
from shodan_report.evaluation.evaluators.registry import ServiceEvaluatorRegistry
from shodan_report.evaluation.config import EvaluationConfig

# Test-Service: MySQL mit CVEs und alter Version
test_service = Service(
    port=3306,
    transport="tcp",
    product="MySQL",
    version="5.7.33",
    vulnerabilities=[
        {"id": "CVE-2023-12345", "cvss": 9.8},
        {"id": "CVE-2023-56789", "cvss": 8.5}
    ]
)

config = EvaluationConfig()
registry = ServiceEvaluatorRegistry(config)

# Evaluierung sollte kombinieren:
# 1. DatabaseEvaluator: ~3 Punkte (unverschlüsselte DB)
# 2. CVEEvaluator: 4 Punkte (2 kritische CVEs)
# 3. VersionEvaluator: 5 Punkte (EOL Version)
# Gesamt: ~12 Punkte!

risk = registry.evaluate_service(test_service)
print(f"Total risk score: {risk.risk_score}")
print(f"Message: {risk.message}")
print(f"Is critical: {risk.is_critical}")
print(f"Recommendations: {risk.recommendations}")