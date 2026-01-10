from typing import List
from .risk_level import RiskLevel
from .business_risk import BusinessRisk
from .models import EvaluationResult

def prioritize_risk(evaluation: EvaluationResult) -> BusinessRisk:

    # 1. Kritische technische Issues werden sofort zu Business CRITICAL
    if evaluation.risk == RiskLevel.CRITICAL:
        return BusinessRisk.CRITICAL
    
    # 2. HIGH technisches Risiko wird auch Business CRITICAL
    if evaluation.risk == RiskLevel.HIGH:
        return BusinessRisk.CRITICAL
    
    # 3. Für zusätzliche Checks
    for point in evaluation.critical_points:
        if "Kritischer Dienst gefunden" in point:
            return BusinessRisk.CRITICAL
    
    # 4. MEDIUM wird zu ATTENTION
    if evaluation.risk == RiskLevel.MEDIUM:
        return BusinessRisk.ATTENTION
    
    # 5. Alles andere ist MONITOR
    return BusinessRisk.MONITOR


def technical_to_business_risk(technical_risk: RiskLevel, critical_points: List[str] = None) -> BusinessRisk:

    if critical_points is None:
        critical_points = []
    
    if technical_risk == RiskLevel.CRITICAL:
        return BusinessRisk.CRITICAL
    elif technical_risk == RiskLevel.HIGH:
        return BusinessRisk.CRITICAL
    elif technical_risk == RiskLevel.MEDIUM:
        return BusinessRisk.ATTENTION
    else:
        return BusinessRisk.MONITOR