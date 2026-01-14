from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk
from .helpers import create_unencrypted_service_risk


class HTTPSEvaluator(ServiceEvaluator):
    def applies_to(self, service: Service) -> bool:
        web_ports = {80, 8080, 8081}
        return service.port in web_ports

    def evaluate(self, service: Service) -> ServiceRisk:
        if service.ssl_info or service.port in [443, 8443]:
            return ServiceRisk(risk_score=0)

        version_risk = self._check_version_risk(service.version or "")

        return create_unencrypted_service_risk(
            service=service,
            base_score=1,
            version_risk=version_risk,
            message_prefix="HTTP",
            is_critical=False,
            recommendations=["Auf HTTPS umstellen", "Automatische Umleitung von HTTP zu HTTPS"],
            should_exclude_from_critical=True,
        )
