# quick_test.py
from shodan_report.evaluation import EvaluationEngine
from shodan_report.parsing.utils import parse_shodan_host

print("=== QUICK SANITY CHECK ===")

# Minimaler Test
test_minimal = {
    "ip_str": "test",
    "data": [{"port": 3306, "transport": "tcp", "product": "MySQL", "version": "5.7.33"}],
    "open_ports": [3306]
}

snapshot = parse_shodan_host(test_minimal)
engine = EvaluationEngine()
result = engine.evaluate(snapshot)

print(f"✅ EvaluationEngine funktioniert: {result.risk.value}")
print(f"✅ Exposure-Score: {result.exposure_score}/5")
print("✅ System ist betriebsbereit!")