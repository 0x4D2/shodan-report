# debug_import_test.py
from shodan_report.evaluation import EvaluationEngine
from shodan_report.evaluation import EvaluationResult
from shodan_report.evaluation import RiskLevel

print("✅ EvaluationEngine importiert:", EvaluationEngine)
print("✅ EvaluationResult importiert:", EvaluationResult)
print("✅ RiskLevel importiert:", RiskLevel)

# Optional: Test ob alte Evaluation auch noch da ist
try:
    from shodan_report.evaluation import Evaluation
    print("⚠️  Alte Evaluation verfügbar (deprecated):", Evaluation)
except ImportError:
    print("❌ Alte Evaluation nicht verfügbar")