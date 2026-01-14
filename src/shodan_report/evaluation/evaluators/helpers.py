from typing import List, Optional
from .base import ServiceRisk
from shodan_report.models import Service


def create_unencrypted_service_risk(
    service: Service,
    base_score: int,
    version_risk: int = 0,
    message_prefix: Optional[str] = None,
    is_critical: bool = True,
    recommendations: Optional[List[str]] = None,
    should_exclude_from_critical: bool = False,
) -> ServiceRisk:
    """Create a standardized ServiceRisk for unencrypted/public services.

    Returns a ServiceRisk with a helpful message, combined score and
    `critical_points` populated with the message when `is_critical`.
    """
    if recommendations is None:
        recommendations = []

    product_info = service.product or "Service"
    version_info = f" {service.version}" if getattr(service, "version", None) else ""
    prefix = message_prefix or product_info
    message = f"{prefix}{version_info} öffentlich erreichbar auf Port {service.port}"

    total_score = base_score + (version_risk or 0)

    critical_points = [message] if is_critical else []

    # TODO: If more service-types share similar recommendations or
    # message patterns, consider adding small factory functions such as
    # `create_database_risk`, `create_http_risk`, etc., or accept a
    # `standard_recommendations` param sourced from `config.weights`.
    return ServiceRisk(
        risk_score=total_score,
        message=message,
        is_critical=is_critical,
        recommendations=recommendations,
        should_exclude_from_critical=should_exclude_from_critical,
        critical_points=critical_points,
    )
