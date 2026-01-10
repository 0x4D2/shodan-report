from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk

class SSHEvaluator(ServiceEvaluator):
    def applies_to(self, service: Service) -> bool:
        return service.port == 22 or "ssh" in (service.product or "").lower()
    
    def evaluate(self, service: Service) -> ServiceRisk:
        version = (service.version or "").lower()
        product = (service.product or "").lower()
        
        if "openssh" in product:
            if version.startswith("9."):
                return ServiceRisk(risk_score=0)
            elif version.startswith("8."):
                return ServiceRisk(risk_score=0)
            elif version.startswith("7."):
                return ServiceRisk(
                    risk_score=1,
                    message=f"SSH (ältere Version {version}) auf Port {service.port}"
                )
            else:
                return ServiceRisk(
                    risk_score=2,
                    message=f"SSH (veraltete, nicht unterstützte Version {version}) auf Port {service.port}",
                    recommendations=["OpenSSH auf aktuelle Version aktualisieren"]
                )
        else:
            return ServiceRisk(
                risk_score=1,
                message=f"SSH (nicht OpenSSH) auf Port {service.port}"
            )