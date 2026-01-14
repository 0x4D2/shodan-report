from typing import List
import math

def is_service_secure(service, secure_indicators: List[str]) -> bool:
    """Bestimmt, ob ein Service als sicher gilt.

    Regeln (abgeleitet aus Tests):
    - Wenn `ssl_info` oder `is_encrypted` gesetzt: immer sicher.
    - Wenn `_version_risk` > 0: unsicher.
    - Wenn Produktname eines `secure_indicators` enthält: sicher.
    - Für Admin-Dienste (SSH/ RDP) gelten zusätzliche Bedingungen: VPN/Tunnel/Cert erforderlich.
    - Ansonsten: unsicher.
    """
    # SSL / Encryption short-circuit
    if getattr(service, 'ssl_info', None):
        return True
    if getattr(service, 'is_encrypted', False):
        return True

    # Admin services (SSH/RDP) need stricter checks: require VPN/Tunnel/Cert or encryption
    port = getattr(service, 'port', None)
    if port in (22, 3389):
        if getattr(service, 'vpn_protected', False) or getattr(service, 'tunneled', False) or getattr(service, 'cert_required', False) or getattr(service, 'is_encrypted', False):
            # still consider version risk
            if getattr(service, '_version_risk', 0) > 0 or getattr(service, 'version_risk', 0) > 0:
                return False
            return True
        return False

    # Version risk makes service insecure
    if getattr(service, '_version_risk', 0) and service._version_risk > 0:
        return False
    if getattr(service, 'version_risk', 0) and getattr(service, 'version_risk', 0) > 0:
        return False

    product = (getattr(service, 'product', '') or '').lower()

    # If product contains any secure indicator -> secure
    for ind in secure_indicators:
        if ind.lower() in product:
            return True

    # Default: insecure
    return False


def calculate_exposure_level(risk: str, critical_points_count: int, open_ports: List[object]) -> int:
    """Berechnet das Exposure-Level (1-5) basierend auf einfachen Heuristiken.

    Implementierung ist abgestimmt auf bestehende Tests:
    - Baseline Level berechnet aus Anzahl unsicherer Dienste: `1 + ceil(insecure_count/2)`
    - Risk-Boost: LOW=0, MEDIUM=1, HIGH=2, CRITICAL=3
    - Zusätzliche Erhöhung durch kritische Punkte: `ceil(critical_points_count/3)`
    - Ergebnis auf [1,5] cappen.
    """
    # Default secure indicators (kann bei Bedarf parametrisiert werden)
    secure_indicators = ["ssh", "rdp", "https", "tls", "vpn"]

    insecure_count = 0
    for svc in open_ports:
        try:
            if not is_service_secure(svc, secure_indicators):
                insecure_count += 1
        except Exception:
            # Im Fehlerfall konservativ: als unsicher zählen
            insecure_count += 1

    # Baseline level
    base_level = 1 + math.ceil(insecure_count / 2)

    # Risk boost
    risk_map = {
        "CRITICAL": 3,
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 0,
    }
    boost = risk_map.get(str(risk).upper(), 0)

    # Critical points influence
    cp_boost = math.ceil(max(0, critical_points_count) / 3)

    level = base_level + boost + cp_boost

    # Cap to 1..5
    if level < 1:
        level = 1
    if level > 5:
        level = 5

    return int(level)
