from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk


class GenericServiceEvaluator(ServiceEvaluator):
    def applies_to(self, service: Service) -> bool:
        # Fallback für alle anderen Services
        return True

    def evaluate(self, service: Service) -> ServiceRisk:
        # Default: kein Risiko für unbekannte Dienste
        version_risk = self._check_version_risk(service.version or "")

        if version_risk > 0:
            return ServiceRisk(
                risk_score=version_risk,
                message=f"Veraltete Version auf Port {service.port}",
                recommendations=["Software aktualisieren"],
            )

        return ServiceRisk(risk_score=0)
