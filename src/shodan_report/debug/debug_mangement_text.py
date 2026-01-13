# debug_management_text_fixed.py
from shodan_report.evaluation.models import EvaluationResult
from shodan_report.evaluation.risk_prioritization import BusinessRisk, RiskLevel
from shodan_report.reporting.management_text import generate_management_text

print("=== Test mit korrekter EvaluationResult ===")

# Korrekte Erstellung
result1 = EvaluationResult(
    ip="217.154.224.104",
    risk=RiskLevel.CRITICAL,
    exposure_score=5,
    critical_points=["MySQL auf Port 3306", "SSH ohne Authentifizierung"]
)

result2 = EvaluationResult(
    ip="111.170.152.60", 
    risk=RiskLevel.LOW,
    exposure_score=2,
    critical_points=[]
)

print("✓ EvaluationResult Instanzen erstellt")

# Test der Funktion
print("\n=== Test generate_management_text ===")

text1 = generate_management_text(BusinessRisk.CRITICAL, result1)
print(f"\n1. CRITICAL Case (mit critical_points):")
print(f"Länge: {len(text1)} Zeichen")
print(f"Erste 200 Zeichen: {text1[:200]}...")

text2 = generate_management_text(BusinessRisk.MONITOR, result2)
print(f"\n2. MONITOR Case (ohne critical_points):")
print(f"Länge: {len(text2)} Zeichen")
print(f"Erste 200 Zeichen: {text2[:200]}...")

print("\n✅ Alle Tests erfolgreich!")