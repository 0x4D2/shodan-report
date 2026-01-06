from enum import Enum
from shodan_report.evaluation.evaluation import Evaluation, RiskLevel

class BusinessRisk(Enum):
    CRITICAL = "critical"
    ATTENTION = "attention"
    MONITOR = "monitor"

def prioritize_risk(evaluation: Evaluation) -> BusinessRisk:
    
    for point in evaluation.critical_points:
        if "Kritischer Dienst gefunden" in point:
            return BusinessRisk.CRITICAL

    if evaluation.risk == RiskLevel.HIGH:
        return BusinessRisk.CRITICAL

    if evaluation.risk == RiskLevel.MEDIUM:
        return BusinessRisk.ATTENTION

    return BusinessRisk.MONITOR
