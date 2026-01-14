# debug_evaluation_engine.py
from shodan_report.models import Service, AssetSnapshot
from shodan_report.evaluation import EvaluationEngine
from shodan_report.parsing.utils import parse_shodan_host
import json

# Erstelle Test-Daten direkt (keine JSON-Datei benötigt)
test_data = {
    "ip_str": "192.168.1.1",
    "data": [
        {
            "port": 3306,
            "transport": "tcp",
            "product": "MySQL",
            "version": "5.7.33",
            "vulns": [
                {"id": "CVE-2023-12345", "cvss": 9.8},
                {"id": "CVE-2023-56789", "cvss": 8.5},
            ],
        }
    ],
    "open_ports": [3306],
}

print("=== TEST: Evaluation Engine mit CVEs und EOL ===")

# Parse zu Snapshot
snapshot = parse_shodan_host(test_data)
print(f"Parsed {len(snapshot.services)} services")

# Teste Service direkt
service = snapshot.services[0]
print(f"\n=== SERVICE DETAILS ===")
print(f"Port: {service.port}")
print(f"Product: {service.product}")
print(f"Version: {service.version}")
print(f"Has vulnerabilities: {hasattr(service, 'vulnerabilities')}")
if hasattr(service, "vulnerabilities"):
    print(f"Number of vulnerabilities: {len(service.vulnerabilities)}")

# Nutze Evaluation Engine
engine = EvaluationEngine()
result = engine.evaluate(snapshot)

print(f"\n=== EVALUATION RESULT ===")
print(f"IP: {result.ip}")
print(f"Risiko-Level: {result.risk.value}")
print(f"Exposure-Score: {result.exposure_score}/5")
print(f"Kritische Punkte: {len(result.critical_points)}")

for i, point in enumerate(result.critical_points):
    print(f"  {i+1}. {point}")

print(f"\nEmpfehlungen: {len(result.recommendations)}")
for rec in result.recommendations[:3]:
    print(f"  • {rec}")

# Prüfe ob kritisch
if result.risk.value == "critical":
    print("\n✅ SUCCESS: MySQL wird korrekt als KRITISCH bewertet!")
else:
    print(f"\n❌ PROBLEM: MySQL sollte 'critical' sein, ist aber '{result.risk.value}'")
    print(f"   Critical points vorhanden: {len(result.critical_points)}")
    print(f"   Exposure score: {result.exposure_score}/5")

    # Debug: Zeige was in critical_points ist
    print(f"\n   Critical points Inhalt:")
    for i, point in enumerate(result.critical_points):
        print(f"   {i+1}. '{point[:50]}...'")

# Zusätzlich: Teste Registry direkt
print(f"\n=== DIRECT REGISTRY TEST ===")
from shodan_report.evaluation.evaluators.registry import ServiceEvaluatorRegistry
from shodan_report.evaluation.config import EvaluationConfig

config = EvaluationConfig()
registry = ServiceEvaluatorRegistry(config)
risk = registry.evaluate_service(service)

print(f"Registry risk score: {risk.risk_score}")
print(f"Registry has critical_points: {hasattr(risk, 'critical_points')}")
if hasattr(risk, "critical_points"):
    print(f"Registry critical_points count: {len(risk.critical_points)}")
    for i, point in enumerate(risk.critical_points):
        print(f"  {i+1}. {point}")
