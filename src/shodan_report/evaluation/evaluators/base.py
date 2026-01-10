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
    
    def __post_init__(self):
        if self.recommendations is None:
            self.recommendations = []

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
    
    def _is_secure(self, service: 'Service') -> bool:
        """Prüft ob Service sicher ist (TLS/SSL)"""
        if service.ssl_info:
            return True
            
        product = (service.product or "").lower()
        for indicator in self.config.weights.secure_indicators:
            if indicator in product:
                return True
        return False