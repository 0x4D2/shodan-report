# debug_real_management.py
import json
from shodan_report.parsing.utils import parse_shodan_host
from shodan_report.evaluation import EvaluationEngine

# Beispiel-Daten mit MySQL und CVEs
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

print("=== TEST: Intelligente Evaluation Engine ===")

# Parse zu Snapshot
snapshot = parse_shodan_host(test_data)
print(f"Parsed {len(snapshot.services)} services")

# Nutze Evaluation Engine
engine = EvaluationEngine()
result = engine.evaluate(snapshot)

print(f"\n=== ERGEBNIS ===")
print(f"IP: {result.ip}")
print(f"Risiko-Level: {result.risk.value}")
print(f"Exposure-Score: {result.exposure_score}/5")
print(f"Kritische Punkte: {len(result.critical_points)}")

for i, point in enumerate(result.critical_points[:3]):
    print(f"  {i+1}. {point}")

print(f"\nEmpfehlungen:")
for rec in result.recommendations[:3]:
    print(f"  • {rec}")

# Prüfe ob kritisch
if result.risk.value in ["CRITICAL", "HIGH"]:
    print("\n✅ SUCCESS: MySQL wird korrekt als KRITISCH bewertet!")
else:
    print(f"\n❌ PROBLEM: MySQL sollte kritisch sein, ist aber {result.risk.value}")
