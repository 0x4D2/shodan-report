from typing import List
from shodan_report.models import AssetSnapshot, Service
from .config import EvaluationConfig
from .evaluators.registry import ServiceEvaluatorRegistry
from .models import EvaluationResult
from .risk_level import RiskLevel

class EvaluationEngine:
    def __init__(self, config: EvaluationConfig = None):
        self.config = config or EvaluationConfig()
        self.registry = ServiceEvaluatorRegistry(self.config)
    
    def evaluate(self, snapshot: AssetSnapshot) -> EvaluationResult:
        """
        Führt die Evaluation durch (neue Version).
        """
        critical_points = []
        recommendations = []
        total_risk_score = 0
        
        # 1. Services analysieren
        for service in snapshot.services:
            risk_result = self.registry.evaluate_service(service)
            
            if risk_result.message:
                if risk_result.is_critical:
                    critical_points.append(risk_result.message)
                elif not risk_result.should_exclude_from_critical:
                    # Empfehlung
                    recommendations.append(risk_result.message)
            
            if risk_result.recommendations:
                recommendations.extend(risk_result.recommendations)
            
            total_risk_score += risk_result.risk_score
        
        # 2. Port-Exposure berechnen
        exposure_score = self._calculate_exposure_score(
            snapshot.services, 
            total_risk_score
        )
        
        # 3. Risiko-Level bestimmen
        risk_level = self._determine_risk_level(critical_points, exposure_score)
        
        return EvaluationResult(
            ip=snapshot.ip,
            risk=risk_level,
            critical_points=critical_points,
            recommendations=recommendations,
            exposure_score=exposure_score
        )
    
    def _calculate_exposure_score(self, services: List[Service], risk_score: int) -> int:
        """Berechnet Exposure-Score 1-5"""
        num_ports = len(services)
        
        if risk_score >= 10 or num_ports > 30:
            return 5
        elif risk_score >= 7 or num_ports > 20:
            return 4
        elif risk_score >= 4 or num_ports > 15:
            return 3
        elif risk_score >= 2 or num_ports > 10:
            return 2
        else:
            return 1
    
    def _determine_risk_level(self, critical_points: List[str], exposure_score: int) -> RiskLevel:
        """Bestimmt das technische Risiko-Level"""
        # Prüfe auf kritische Services
        for point in critical_points:
            point_lower = point.lower()
            if any(keyword in point_lower for keyword in 
                  ["rdp", "vnc", "telnet ohne", "unverschlüsselt"]):
                return RiskLevel.CRITICAL
        
        # Exposure-basierte Bewertung
        if exposure_score >= 4:
            return RiskLevel.HIGH
        elif exposure_score >= 3:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW


def evaluate_snapshot(snapshot: AssetSnapshot) -> EvaluationResult:
    engine = EvaluationEngine()
    return engine.evaluate(snapshot)