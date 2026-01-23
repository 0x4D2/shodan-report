# debug_engine_integration.py
from shodan_report.evaluation.evaluation_engine import EvaluationEngine

print("🔧 TEST ENGINE INTEGRATION")
print("=" * 50)

engine = EvaluationEngine()

# Simuliere einen MySQL-Service mit CVEs
test_service = {
    "service": "mysql",
    "version": "8.0.33",
    "cves": ["CVE-2025-50000", "CVE-2025-50001", ...],  # deine 88 CVEs
    "port": 3306,
    "is_public": True,
    "transport": "tcp",
}

print("1. Prüfe welche Evaluatoren aktiviert werden:")
active = engine._get_active_evaluators(test_service)
print(f"   Aktive Evaluatoren: {[e.__class__.__name__ for e in active]}")

print("\n2. Führe Engine aus:")
results = engine.evaluate_service(test_service)
print(f"   Gesamt-Score: {results['risk_score']}")
print(f"   Evaluator-Ergebnisse: {len(results['evaluator_results'])}")

print("\n3. Critical Points sammeln:")
all_points = []
for eval_result in results["evaluator_results"]:
    points = eval_result.get("critical_points", [])
    if points:
        print(f"   - {eval_result['evaluator_name']}: {points}")
        all_points.extend(points)

print(f"\n📋 GESAMTE CRITICAL POINTS: {len(all_points)}")
for i, point in enumerate(all_points[:10], 1):
    print(f"   {i}. {point}")
