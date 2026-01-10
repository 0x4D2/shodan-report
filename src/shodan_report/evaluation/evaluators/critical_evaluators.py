from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk

class RDPEvaluator(ServiceEvaluator):
    def applies_to(self, service: Service) -> bool:
        return service.port == 3389 or ("rdp" in (service.product or "").lower())
    
    def evaluate(self, service: Service) -> ServiceRisk:
        if not self._is_secure(service):
            return ServiceRisk(
                risk_score=self.config.weights.high_risk_services["rdp_unencrypted"],
                message=f"RDP öffentlich erreichbar ohne Verschlüsselung auf Port {service.port}",
                is_critical=True,
                recommendations=["RDP hinter VPN schützen", "Nur mit Zertifikaten erlauben"]
            )
        return ServiceRisk(risk_score=0)

class VNCEvaluator(ServiceEvaluator):
    def applies_to(self, service: Service) -> bool:
        return service.port == 5900 or ("vnc" in (service.product or "").lower())
    
    def evaluate(self, service: Service) -> ServiceRisk:
        if not self._is_secure(service):
            return ServiceRisk(
                risk_score=self.config.weights.high_risk_services["vnc_unencrypted"],
                message=f"VNC öffentlich erreichbar ohne Verschlüsselung auf Port {service.port}",
                is_critical=True,
                recommendations=["VNC hinter SSH-Tunnel betreiben", "VPN verwenden"]
            )
        return ServiceRisk(risk_score=0)

class TelnetEvaluator(ServiceEvaluator):
    def applies_to(self, service: Service) -> bool:
        return service.port == 23 or ("telnet" in (service.product or "").lower())
    
    def evaluate(self, service: Service) -> ServiceRisk:
        return ServiceRisk(
            risk_score=self.config.weights.high_risk_services["telnet"],
            message=f"Telnet (unverschlüsselt) auf Port {service.port}",
            is_critical=True,
            recommendations=["Auf SSH umstellen", "Dienst deaktivieren"]
        )