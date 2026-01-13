# debug_version_evaluator.py
from shodan_report.evaluation.config import EvaluationConfig
from shodan_report.evaluation.evaluators.version_evaluator import VersionEvaluator

config = EvaluationConfig()
evaluator = VersionEvaluator(config)

# Teste MySQL 5.7.0
product = "MySQL"
version = "5.7.0"

print(f"Testing: {product} {version}")
print(f"Normalized product: {evaluator._normalize_product_name(product)}")
print(f"Normalized version: {evaluator._normalize_version(version)}")

# Manuell prüfen
product_key = evaluator._normalize_product_name(product)
print(f"\nProduct key: {product_key}")
print(f"In VERSION_CHECKS: {product_key in evaluator.VERSION_CHECKS}")

if product_key in evaluator.VERSION_CHECKS:
    check_data = evaluator.VERSION_CHECKS[product_key]
    print(f"\nCheck data for {product_key}:")
    print(f"  secure_min: {check_data['secure_min']}")
    print(f"  critical_max: {check_data['critical_max']}")
    print(f"  eol_versions: {check_data['eol_versions']}")
    
    normalized_version = evaluator._normalize_version(version)
    print(f"\nNormalized version: '{normalized_version}'")
    
    # Prüfe EOL
    is_eol = evaluator._is_version_eol(product_key, normalized_version, check_data["eol_versions"])
    print(f"Is EOL: {is_eol}")
    
    # Prüfe critical
    is_critical = evaluator._compare_versions(normalized_version, "<=", check_data["critical_max"])
    print(f"Is critical (<= {check_data['critical_max']}): {is_critical}")
    
    # Prüfe outdated
    is_outdated = evaluator._compare_versions(normalized_version, "<", check_data["secure_min"])
    print(f"Is outdated (< {check_data['secure_min']}): {is_outdated}")

# Berechne Score
score = evaluator.calculate_version_risk(product, version)
print(f"\nFinal risk score: {score}")