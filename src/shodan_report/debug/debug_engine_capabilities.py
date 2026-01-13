# debug_cve_scores.py
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from shodan_report.evaluation.evaluators.cve_evaluator import CVEEvaluator
from shodan_report.evaluation.config import EvaluationConfig
from shodan_report.models import Service

def test_cve_score_calculation():
    """Testet CVE Score Berechnung."""
    
    print("🔍 TEST CVE SCORE CALCULATION")
    print("="*50)
    
    config = EvaluationConfig()
    evaluator = CVEEvaluator(config)
    
    # Service mit CVEs
    service = Service(
        port=3306,
        transport="tcp",
        product="MySQL",
        version="8.0.33",
        raw={
            "vulns": [f"CVE-2025-{50000 + i}" for i in range(24)] + 
                     [f"CVE-2024-{40000 + i}" for i in range(64)]
        }
    )
    
    # Direkt die Helper-Methoden testen
    raw_vulns = service.raw.get('vulns', [])
    cve_objects = evaluator._convert_to_cve_objects(raw_vulns)
    
    print(f"\n📊 CVE OBJECTS ANALYSIS:")
    print(f"  Total CVE objects: {len(cve_objects)}")
    
    # CVSS Verteilung
    cvss_counts = {}
    for cve in cve_objects[:10]:  # Nur erste 10 prüfen
        cvss = cve.cvss
        cvss_counts[cvss] = cvss_counts.get(cvss, 0) + 1
    
    print(f"  CVSS distribution (first 10): {cvss_counts}")
    
    # Manuelle _calculate_cve_risk_score
    print(f"\n🔢 MANUAL RISK SCORE CALCULATION:")
    total_cves = len(cve_objects)
    critical_cves = sum(1 for cve in cve_objects if cve.cvss >= 9.0)
    high_cves = sum(1 for cve in cve_objects if 7.0 <= cve.cvss < 9.0)
    medium_cves = sum(1 for cve in cve_objects if 4.0 <= cve.cvss < 7.0)
    
    print(f"  total_cves: {total_cves}")
    print(f"  critical_cves (cvss>=9.0): {critical_cves}")
    print(f"  high_cves (cvss 7.0-8.9): {high_cves}")
    print(f"  medium_cves (cvss 4.0-6.9): {medium_cves}")
    print(f"  high_cves >= 2: {high_cves >= 2}")
    print(f"  total_cves >= 10: {total_cves >= 10}")
    
    # Debug: Schau dir die ersten 5 CVEs an
    print(f"\n🔍 FIRST 5 CVE OBJECTS:")
    for i, cve in enumerate(cve_objects[:5]):
        print(f"  {i+1}. {cve.id}: cvss={cve.cvss}, severity={cve.severity}")
    
    # Teste die Methode direkt
    print(f"\n🎯 DIRECT METHOD CALL:")
    risk_score = evaluator._calculate_cve_risk_score(cve_objects)
    print(f"  _calculate_cve_risk_score result: {risk_score}")
    
    # Warum gibt es 0 zurück? Prüfe die Logik
    print(f"\n🧮 CHECKING LOGIC:")
    if critical_cves >= 3:
        print(f"  critical_cves >= 3: TRUE → return 5")
    elif critical_cves >= 1:
        print(f"  critical_cves >= 1: TRUE → return 4") 
    elif high_cves >= 2:
        print(f"  high_cves >= 2: TRUE → return 4")
    elif total_cves >= 10:
        print(f"  total_cves >= 10: TRUE → return 3")
    elif total_cves >= 5:
        print(f"  total_cves >= 5: TRUE → return 2")
    elif total_cves >= 1:
        print(f"  total_cves >= 1: TRUE → return 1")
    else:
        print(f"  All conditions FALSE → return 0")

if __name__ == "__main__":
    test_cve_score_calculation()