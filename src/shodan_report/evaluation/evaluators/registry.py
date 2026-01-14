from typing import List
from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk


class ServiceEvaluatorRegistry:
    def __init__(self, config):
        self.config = config
        self.evaluators: List[ServiceEvaluator] = self._init_evaluators()

    def _init_evaluators(self) -> List[ServiceEvaluator]:
        """Initialisiert alle Evaluatoren in der richtigen Reihenfolge"""
        # Import hier um Zirkuläre Dependencies zu vermeiden
        from .critical_evaluators import RDPEvaluator, VNCEvaluator, TelnetEvaluator
        from .database_evaluators import DatabaseEvaluator
        from .web_evaluators import HTTPSEvaluator
        from .ssh_evaluator import SSHEvaluator
        from .mail_evaluator import MailServiceEvaluator
        from .generic_evaluator import GenericServiceEvaluator
        from .cve_evaluator import CVEEvaluator
        from .version_evaluator import VersionEvaluator

        return [
            # Kritische Services zuerst
            RDPEvaluator(self.config),
            VNCEvaluator(self.config),
            TelnetEvaluator(self.config),
            # Datenbanken
            DatabaseEvaluator(self.config),
            # Web Services
            HTTPSEvaluator(self.config),
            SSHEvaluator(self.config),
            # Mail Services
            MailServiceEvaluator(self.config),
            # Add-on Evaluatoren
            CVEEvaluator(self.config),
            VersionEvaluator(self.config),
            # Generischer Fallback
            GenericServiceEvaluator(self.config),
        ]

    def evaluate_service(self, service: Service) -> ServiceRisk:
        """Kombiniert ALLE passenden Evaluatoren."""
        total_risk = ServiceRisk(risk_score=0)
        critical_messages = []  # Extra Liste für kritische Messages
        normal_messages = []  # Extra Liste für normale Messages

        for evaluator in self.evaluators:
            if evaluator.applies_to(service):
                risk = evaluator.evaluate(service)

                # Risiko-Scores kombinieren
                total_risk.risk_score += risk.risk_score

                # Messages sammeln
                if risk.message:
                    if risk.is_critical and not risk.should_exclude_from_critical:
                        critical_messages.append(risk.message)
                    elif not risk.should_exclude_from_critical:
                        normal_messages.append(risk.message)

                # Critical-Flag kombinieren
                if risk.is_critical:
                    total_risk.is_critical = True

                # Recommendations kombinieren
                for rec in risk.recommendations:
                    if rec not in total_risk.recommendations:
                        total_risk.recommendations.append(rec)

        # Kritische Messages zu critical_points hinzufügen
        if critical_messages:
            total_risk.critical_points = critical_messages  # ← NEU!

        # Normale Messages zu message kombinieren
        if normal_messages:
            total_risk.message = " | ".join(normal_messages)
        elif critical_messages:
            # Falls nur kritische Messages, nehme die erste als Haupt-Message
            total_risk.message = critical_messages[0]

        return total_risk
