from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk


class HTTPSEvaluator(ServiceEvaluator):
    def applies_to(self, service: Service) -> bool:
        web_ports = {80, 8080, 8081}
        return service.port in web_ports

    def evaluate(self, service: Service) -> ServiceRisk:
        if service.ssl_info or service.port in [443, 8443]:
            return ServiceRisk(risk_score=0)

        version_risk = self._check_version_risk(service.version or "")

        return ServiceRisk(
            risk_score=1 + version_risk,
            message=f"HTTP ohne Verschlüsselung auf Port {service.port}",
            is_critical=False,
            should_exclude_from_critical=True,
            recommendations=[
                "Auf HTTPS umstellen",
                "Automatische Umleitung von HTTP zu HTTPS",
            ],
        )
