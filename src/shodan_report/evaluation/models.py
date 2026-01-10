from dataclasses import dataclass, field
from typing import List, Optional
from .risk_level import RiskLevel

@dataclass
class ServiceRisk:
    risk_score: int = 0
    message: Optional[str] = None
    is_critical: bool = False
    recommendations: List[str] = field(default_factory=list)
    should_exclude_from_critical: bool = False

@dataclass
class EvaluationResult:
    ip: str
    risk: RiskLevel
    critical_points: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    exposure_score: int = 1
    
    # Für backward compatibility - kann später entfernt werden
    @property
    def critical_points(self):
        # Gibt kritische Punkte zurück (keine Empfehlungen)
        return [p for p in self._critical_points if not self._is_recommendation(p)]
    
    @critical_points.setter
    def critical_points(self, value):
        self._critical_points = value
    
    def _is_recommendation(self, point: str) -> bool:
        return any(keyword in point.lower() for keyword in 
                  ["empfohlen", "empfehlung", "sollte", "könnte"])