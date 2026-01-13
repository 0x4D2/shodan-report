from typing import List
from shodan_report.models import Service

def is_service_secure(service: Service, secure_indicators: List[str]) -> bool:
    if service.ssl_info or service.is_encrypted:
        return True

    product = (service.product or "").lower()

    admin_services = ["ssh", "rdp", "vnc", "telnet"]
    is_admin_service = (
        service.port in [22, 3389, 5900, 23] or 
        any(x in product for x in admin_services)
    )

    if is_admin_service:
        # Admin-Dienste sind nur sicher mit zusätzlichem Schutz
        return service.vpn_protected or service.tunneled or service.cert_required

    for indicator in secure_indicators:
        if indicator in product:
            return True

    version_risk = getattr(service, "_version_risk", 0)
    if version_risk > 0:
        return False

    # Standard unsicher
    return False

def calculate_exposure_level(
    risk: str,
    critical_points_count: int,
    open_ports: List[Service] = None
) -> int:
    # 1. Zähle unsichere Dienste
    insecure_count = 0
    secure_indicators = ["ssh", "rdp", "https", "tls", "vpn"]
    
    if open_ports:
        for service in open_ports:
            if not is_service_secure(service, secure_indicators):
                insecure_count += 1
    
    # 2. Gewichtete Summe
    weighted_total = critical_points_count + 0.5 * insecure_count
    
    # 3. MAPPING Tabelle für präzise Abstufung
    # weighted_total → tech_exposure
    if weighted_total >= 5.0:
        tech_exposure = 5
    elif weighted_total >= 3.5:
        tech_exposure = 4
    elif weighted_total >= 2.0:
        tech_exposure = 3
    elif weighted_total >= 0.5:  # 1 unsicherer Dienst = Level 2
        tech_exposure = 2
    else:  # weighted_total = 0
        tech_exposure = 1
    
    # 4. Risk-Boost
    risk_boost = {"low": 0, "medium": 1, "high": 2}
    boost = risk_boost.get(str(risk).lower(), 0)
    
    exposure = tech_exposure + boost
    
    return min(5, exposure)