"""Core evaluation primitives: Enums, dataclasses and main evaluator.

Kept small and focused so `evaluation.py` can re-export a stable API.
"""
from enum import Enum
from dataclasses import dataclass, field
from typing import List

from shodan_report.models import AssetSnapshot
from .helpers.eval_helpers import analyze_open_ports, analyze_services


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BusinessRisk(Enum):
    CRITICAL = "critical"
    ATTENTION = "attention"
    MONITOR = "monitor"


@dataclass
class Evaluation:
    ip: str
    risk: RiskLevel
    critical_points: List[str] = field(default_factory=list)
    exposure_score: int = 1


def evaluate_snapshot(snapshot: AssetSnapshot) -> Evaluation:
    """Evaluate a snapshot and return an `Evaluation`.

    This function delegates open-port / per-service inspection to the
    pure helpers in `helpers.eval_helpers` so the core stays small and
    testable.
    """
    critical_points: List[str] = []
    risk_score = 0

    port_score, port_points = analyze_open_ports(snapshot.services)
    svc_score, svc_points = analyze_services(snapshot.services)

    risk_score += port_score + svc_score
    critical_points.extend(port_points)
    critical_points.extend(svc_points)

    # 3. Determine risk level (delegated to helper for clarity)
    risk = _calculate_risk_level(critical_points, risk_score)

    # 4. Exposure Score (1-5)
    if risk_score >= 5:
        exposure = 5
    elif risk_score >= 3:
        exposure = 4
    elif risk_score >= 2:
        exposure = 3
    elif risk_score >= 1:
        exposure = 2
    else:
        exposure = 1

    return Evaluation(
        ip=snapshot.ip,
        risk=risk,
        critical_points=critical_points,
        exposure_score=exposure,
    )


def _calculate_risk_level(critical_points: List[str], exposure_score: int) -> RiskLevel:
    """Determine a `RiskLevel` from critical findings and exposure score.

    Kept case-insensitive and aligned with previous behaviour.
    """
    # Prüfe auf KRITISCHE Probleme
    for point in critical_points:
        point_lower = point.lower()
        if "rdp" in point_lower or "vnc" in point_lower or "telnet" in point_lower:
            return RiskLevel.CRITICAL

    # Normale Bewertung nach risk score (compatible with previous logic)
    if exposure_score >= 3:
        return RiskLevel.HIGH
    elif exposure_score >= 1:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW
