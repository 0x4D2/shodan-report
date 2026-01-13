# debug_evaluator_flow.py
from shodan_report.evaluation.evaluators.cve_evaluator import CVEEvaluator

# Mock-Konfiguration erstellen
mock_config = {
    'cve_scoring': {
        'critical_threshold': 9.0,
        'high_threshold': 7.0,
        'medium_threshold': 4.0
    }
}

print("🚀 TESTE GANZEN EVALUATOR FLOW")
print("=" * 50)

# 1. Test mit echten Daten
evaluator = CVEEvaluator(mock_config)

# Erstelle 88 Test-CVEs
test_cves = [f"CVE-2025-{50000 + i}" for i in range(88)]

test_data = {
    "cves": test_cves,
    "service": "mysql",
    "port": 3306
}

print(f"Test mit {len(test_cves)} CVEs")

# 2. Rufe evaluate() direkt auf
result = evaluator.evaluate(test_data)
print(f"\n📊 Evaluator Ergebnis:")
print(f"  Score: {result.get('score')}")
print(f"  Critical Points: {result.get('critical_points', [])}")
print(f"  Description: {result.get('description', '')[:150]}...")

# 3. Prüfe ob evaluate() die Methode korrekt aufruft
print("\n🔍 INTERNE METHODEN:")
print(f"  _calculate_cve_risk_score wurde aufgerufen: {'score' in result}")

# 4. Manuell _generate_critical_points prüfen
if result.get('score', 0) >= 4:
    print(f"\n🎯 Score >= 4: {result['score']}")
    try:
        # Verwende Reflektion um private Methode aufzurufen
        points = evaluator._generate_critical_points(test_data, result['score'])
        print(f"  Generierte Points: {points}")
    except Exception as e:
        print(f"  Fehler bei _generate_critical_points: {e}")