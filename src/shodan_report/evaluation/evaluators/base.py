from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING
from dataclasses import dataclass

# Vermeide Zirkuläre Imports
if TYPE_CHECKING:
    from shodan_report.models import Service
    from ..config import EvaluationConfig

@dataclass
class ServiceRisk:
    risk_score: int = 0
    message: Optional[str] = None
    is_critical: bool = False
    recommendations: list = None
    should_exclude_from_critical: bool = False
    critical_points: list = None
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []
        if self.critical_points is None: 
            self.critical_points = []

class ServiceEvaluator(ABC):
    """Basis-Klasse für alle Service-Evaluatoren"""
    
    def __init__(self, config: 'EvaluationConfig'):
        self.config = config
    
    @abstractmethod
    def applies_to(self, service: 'Service') -> bool:
        """Prüft ob dieser Evaluator für den Service zuständig ist"""
        pass
    
    @abstractmethod
    def evaluate(self, service: 'Service') -> ServiceRisk:
        """Führt die Evaluation durch"""
        pass
    
    def _check_version_risk(self, version: str) -> int:
        """Prüft Version auf bekannte Risiko-Indikatoren"""
        if not version:
            return 0
            
        version_lower = version.lower()
        for indicator, risk_val in self.config.weights.vulnerable_indicators.items():
            if indicator in version_lower:
                return risk_val - 1  # Weniger schwer gewichten
        return 0

    # ==================== GEÄNDERT / HINZUGEFÜGT ====================
    def _is_secure(self, service: 'Service') -> bool:
        """
        Prüft, ob ein Service als sicher gilt.
        Berücksichtigt:
        - SSL/TLS
        - sichere Produkt-Indikatoren
        - RDP/VNC/Telnet Besonderheiten (VPN/Tunnel)
        - Versions-Risiken (via _check_version_risk)
        """
        
        # Verschlüsselung prüfen
        if service.ssl_info:
            return True

        product = (service.product or "").lower()
        
        # sichere Produkte
        for indicator in self.config.weights.secure_indicators:
            if indicator in product:
                return True

        # RDP / VNC / Telnet: muss VPN/Tunnel oder Zertifikate nutzen
        if service.port in [3389, 5900, 23] or any(x in product for x in ["rdp", "vnc", "telnet"]):
            if getattr(service, "vpn_protected", False):
                return True
            if getattr(service, "tunneled", False):
                return True
            if getattr(service, "cert_required", False):
                return True
            # sonst kritisch
            return False

        # Versions-Risiko prüfen
        version_risk = self._check_version_risk(service.version)
        if version_risk > 0:
            return False

        # 5️⃣ Standardmäßig unsicher
        return False
    # ==================== ENDE DER ÄNDERUNG ====================
