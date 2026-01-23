from typing import List
import math
from shodan_report.models import AssetSnapshot, Service
from .config import EvaluationConfig
from .evaluators.registry import ServiceEvaluatorRegistry
from .models import EvaluationResult
from .risk_level import RiskLevel
from shodan_report.pdf.helpers.evaluation_helpers import is_service_secure


class EvaluationEngine:
    def __init__(self, config: EvaluationConfig = None):
        self.config = config or EvaluationConfig()
        self.registry = ServiceEvaluatorRegistry(self.config)

    # evaluation_engine.py - evaluate() Methode korrigieren:
    def evaluate(self, snapshot: AssetSnapshot) -> EvaluationResult:
        critical_points = []
        recommendations = []
        total_risk_score = 0

        # 1. Services analysieren
        for service in snapshot.services:
            risk_result = self.registry.evaluate_service(service)

            # ✅ KORREKT: critical_points von ServiceRisk übernehmen
            if hasattr(risk_result, "critical_points") and risk_result.critical_points:
                critical_points.extend(risk_result.critical_points)
            elif risk_result.message and risk_result.is_critical:
                # Fallback für alte Evaluatoren
                critical_points.append(risk_result.message)

            # Recommendations sammeln
            if risk_result.recommendations:
                recommendations.extend(risk_result.recommendations)

            total_risk_score += risk_result.risk_score

        # 2. Port-Exposure berechnen
        exposure_score = self._calculate_exposure_score(
            snapshot.services, total_risk_score, len(critical_points)
        )

        # 3. Risiko-Level bestimmen
        risk_level = self._determine_risk_level(critical_points, exposure_score)

        return EvaluationResult(
            ip=snapshot.ip,
            risk=risk_level,
            critical_points=critical_points,  # ← Jetzt mit allen 3 Punkten!
            recommendations=recommendations,
            exposure_score=exposure_score,
        )

    def _calculate_exposure_score(
        self, services: List[Service], risk_score: int, critical_points_count: int = 0
    ) -> int:
        """Berechnet Exposure-Score 1-5 anhand Shodan-Indikatoren.

        Grundlage ist die Anzahl unsicherer Dienste, die via
        SSL/VPN/Tunnel/Cert-Indikatoren aus Shodan bestimmt wird.
        """
        secure_indicators = getattr(self.config.weights, "secure_indicators", None) or [
            "tls",
            "ssl",
            "https",
            "wss",
        ]

        insecure_count = 0
        for svc in services:
            try:
                if not is_service_secure(svc, secure_indicators):
                    insecure_count += 1
            except Exception:
                insecure_count += 1

        total_ports = len(services)

        # Baseline: 1 + ceil(insecure/4)
        # (konservativer für OSINT-Indikatoren)
        base_level = 1 + math.ceil(insecure_count / 4)

        # Small port-count boost to avoid under-rating hosts with many services
        # (only when many services are also insecure)
        port_boost = 1 if (total_ports >= 10 and insecure_count >= 7) else 0

        level = base_level + port_boost

        if level < 1:
            level = 1
        if level > 5:
            level = 5

        return int(level)

    def _determine_risk_level(
        self, critical_points: List[str], exposure_score: int
    ) -> RiskLevel:
        """Bestimmt das technische Risiko-Level"""
        # Prüfe auf kritische Services
        for point in critical_points:
            point_lower = point.lower()
            if any(
                keyword in point_lower
                for keyword in [
                    "rdp",
                    "vnc",
                    "telnet",
                ]
            ):
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
