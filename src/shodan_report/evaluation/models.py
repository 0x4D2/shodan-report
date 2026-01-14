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
    exposure_score: int

    # Intern
    _critical_points: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    total_services: int = 0
    insecure_services: int = 0

    # ================== NEU: Konstruktor-freundlich ==================
    def __init__(
        self,
        ip: str,
        risk: RiskLevel,
        exposure_score: int,
        critical_points: Optional[List[str]] = None,
        recommendations: Optional[List[str]] = None,
        total_services: int = 0,
        insecure_services: int = 0,
    ):
        self.ip = ip
        self.risk = risk
        self.exposure_score = exposure_score
        self._critical_points = critical_points or []
        self.recommendations = recommendations or []
        self.total_services = total_services
        self.insecure_services = insecure_services

    # ================================================================

    @property
    def critical_points(self) -> List[str]:
        return [p for p in self._critical_points if not self._is_recommendation(p)]

    def add_critical_point(self, point: str):
        self._critical_points.append(point)

    def _is_recommendation(self, point: str) -> bool:
        return any(
            k in point.lower() for k in ["empfohlen", "empfehlung", "sollte", "könnte"]
        )
