# debug_database_evaluator_details.py
from shodan_report.evaluation.evaluators.database_evaluators import DatabaseEvaluator

print("🗄️ DATABASE EVALUATOR MIT CVE DETAILS")
print("=" * 50)

evaluator = DatabaseEvaluator()

# Test mit verschiedenen Daten
test_cases = [
    {
        "service": "mysql",
        "version": "8.0.33",
        "cves": ["CVE-2025-50000", "CVE-2025-50001"],
        "port": 3306,
        "is_public": True,
    },
    {
        "service": "mysql",
        "version": "8.0.33",
        "cves": [],
        "port": 3306,
        "is_public": True,
    },
]

for i, test_data in enumerate(test_cases, 1):
    print(f"\n📊 Testfall {i}:")
    print(f"   MySQL 8.0.33 mit {len(test_data.get('cves', []))} CVEs")

    result = evaluator.evaluate(test_data)
    print(f"   Score: {result.get('score')}")
    print(f"   Description: {result.get('description', '')[:100]}...")

    # Prüfe _generate_critical_points
    if result.get("score", 0) > 0:
        points = evaluator._generate_critical_points(test_data, result["score"])
        print(f"   Critical Points: {points}")
