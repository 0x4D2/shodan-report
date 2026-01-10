from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk

class MailServiceEvaluator(ServiceEvaluator):
    def applies_to(self, service: Service) -> bool:
        mail_ports = {25, 110, 143, 465, 587, 993, 995}
        return service.port in mail_ports
    
    def evaluate(self, service: Service) -> ServiceRisk:
        if service.ssl_info or service.port in [465, 993, 995]:
            return ServiceRisk(risk_score=0)
        
        version_risk = self._check_version_risk(service.version or "")
        
        return ServiceRisk(
            risk_score=1 + version_risk,
            message=f"Mail-Dienst unverschlüsselt auf Port {service.port}",
            recommendations=["Auf TLS/SSL umstellen"]
        )