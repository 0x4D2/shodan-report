from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk
from .helpers import create_unencrypted_service_risk


class DatabaseEvaluator(ServiceEvaluator):
    def applies_to(self, service: Service) -> bool:
        db_ports = {3306, 5432, 27017, 6379, 1433}
        db_products = {"mysql", "postgresql", "mongodb", "redis", "mssql"}

        if service.port in db_ports:
            return True

        product = (service.product or "").lower()
        return any(db in product for db in db_products)

    def evaluate(self, service: Service) -> ServiceRisk:
        if self._is_secure(service):
            return ServiceRisk(risk_score=0)

        version_risk = self._check_version_risk(service.version or "")

        # DETAILLIERTE MESSAGE
        product_info = service.product or "Datenbank"
        version_info = f" {service.version}" if service.version else ""
        message = f"{product_info}{version_info} öffentlich erreichbar auf Port {service.port}"

        return create_unencrypted_service_risk(
            service=service,
            base_score=self.config.weights.high_risk_services.get(
                "database_unencrypted", 3
            ),
            version_risk=version_risk,
            message_prefix=product_info,
            is_critical=True,
            recommendations=[
                "Datenbank hinter Firewall/VPN schützen",
                "IP-Whitelisting verwenden",
            ],
        )
