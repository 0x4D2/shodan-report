# test_management_helpers.py
import json
from shodan_report.evaluation import EvaluationEngine
from shodan_report.parsing.utils import parse_shodan_host
from shodan_report.pdf.helpers.management_helpers import (
    generate_priority_insights,
    generate_priority_recommendations,
    generate_risk_overview
)

# Test-Daten
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
                {"id": "CVE-2023-56789", "cvss": 8.5}
            ]
        }
    ],
    "open_ports": [3306]
}

print("=== TEST: Management Helpers mit Evaluation Engine ===")

# Evaluation berechnen (EINMAL)
snapshot = parse_shodan_host(test_data)
engine = EvaluationEngine()
evaluation_result = engine.evaluate(snapshot)

print(f"Evaluation Result: {evaluation_result.risk.value}, Exposure: {evaluation_result.exposure_score}")

# Teste Insights mit evaluation_result
insights = generate_priority_insights(
    test_data,
    evaluation_result,
    "HIGH"
)

print(f"\n=== INSIGHTS ({len(insights)}) ===")
for i, insight in enumerate(insights):
    print(f"{i+1}. {insight}")

# Teste Recommendations mit evaluation_result
recommendations = generate_priority_recommendations(
    "HIGH",
    test_data,
    evaluation_result
)

print(f"\n=== RECOMMENDATIONS ({len(recommendations)}) ===")
for i, rec in enumerate(recommendations):
    print(f"{i+1}. {rec}")

# Teste Risk Overview
risk_overview = generate_risk_overview(evaluation_result)
print(f"\n=== RISK OVERVIEW ===")
for key, value in risk_overview.items():
    print(f"{key}: {value}")

print("\n✅ TEST COMPLETE")