"""
Evaluation Module - Zentrale Schnittstelle für Risikobewertung.

Diese Datei bietet Backward Compatibility für bestehenden Code.
Für neue Implementierungen die direkten Imports aus den Untermodulen verwenden.
"""

import warnings
from typing import TYPE_CHECKING

# Export alles für einfachen Zugriff
from .risk_level import RiskLevel
from .business_risk import BusinessRisk
from .models import EvaluationResult
from .evaluation_engine import evaluate_snapshot, EvaluationEngine
from .config import EvaluationConfig
from .risk_prioritization import prioritize_risk, technical_to_business_risk

if TYPE_CHECKING:
    from shodan_report.models import AssetSnapshot

# ============================================================================
# BACKWARD COMPATIBILITY
# ============================================================================

class Evaluation(EvaluationResult):
    """
    Alias-Klasse für backward compatibility.
    
    WARNING: Diese Klasse ist deprecated und wird in zukünftigen Versionen entfernt.
    Verwende stattdessen EvaluationResult.
    """
    
    def __init__(self, *args, **kwargs):
        warnings.warn(
            "Die Evaluation-Klasse ist deprecated. Verwende stattdessen EvaluationResult.",
            DeprecationWarning,
            stacklevel=2
        )
        super().__init__(*args, **kwargs)
    
    # Alte Attribute für Kompatibilität
    @property
    def critical_points(self):
        """Gibt nur echte kritische Punkte zurück (keine Empfehlungen)."""
        return [p for p in self._critical_points if not self._is_recommendation(p)]
    
    @critical_points.setter
    def critical_points(self, value):
        self._critical_points = value
    
    @property
    def recommendations(self):
        """Gibt nur Empfehlungen zurück."""
        return [p for p in self._critical_points if self._is_recommendation(p)]
    
    @recommendations.setter 
    def recommendations(self, value):
        # In der alten Logik wurden Empfehlungen in critical_points gespeichert
        self._critical_points = [*self.critical_points, *value]
    
    def _is_recommendation(self, point: str) -> bool:
        """Prüft ob es sich um eine Empfehlung handelt."""
        point_lower = point.lower()
        recommendation_keywords = [
            "empfohlen", "empfehlung", "sollte", "könnte", 
            "umleiten", "umstellen", "aktualisieren"
        ]
        return any(keyword in point_lower for keyword in recommendation_keywords)

# ============================================================================
# KOMPATIBILITÄTS-FUNKTIONEN
# ============================================================================

def evaluate_asset_snapshot(snapshot: 'AssetSnapshot') -> Evaluation:
    """
    Evaluates an asset snapshot and returns an Evaluation object.
    
    WARNING: Diese Funktion ist deprecated. 
    Verwende stattdessen evaluate_snapshot() aus evaluation_engine.
    """
    warnings.warn(
        "evaluate_asset_snapshot() ist deprecated. Verwende evaluate_snapshot()",
        DeprecationWarning,
        stacklevel=2
    )
    
    # Verwende die neue Engine, aber konvertiere zu altem Format
    result = evaluate_snapshot(snapshot)
    
    # Konvertiere zum alten Format für Kompatibilität
    return Evaluation(
        ip=result.ip,
        risk=result.risk,
        critical_points=result.critical_points + result.recommendations,
        exposure_score=result.exposure_score
    )

# ============================================================================
# ALTE KONSTANTEN (für Kompatibilität)
# ============================================================================

# Alte Risikofaktoren als Read-Only Properties
class _LegacyEvaluationConfig:
    """Container für alte Klassenvariablen."""
    
    @property
    def HIGH_RISK_SERVICES(self):
        return {
            "rdp": 5,
            "vnc": 5,
            "telnet": 4,
            "mysql": 4,
            "postgresql": 4,
            "mongodb": 4,
            "redis": 4,
        }
    
    @property
    def SECURE_INDICATORS(self):
        return ["tls", "ssl", "starttls", "https", "wss"]
    
    @property
    def VULNERABLE_INDICATORS(self):
        return {
            "1.0": 2, "2.0": 1, "deprecated": 3, "end-of-life": 4,
            "test": 2, "dev": 2, "alpha": 2, "beta": 1, "rc": 1
        }

# Instanz für Zugriff
_legacy_config = _LegacyEvaluationConfig()

# ============================================================================
# MODULE EXPORTS
# ============================================================================

# Export für einfachen Zugriff
__all__ = [
    # Neue Klassen und Funktionen
    'RiskLevel',
    'BusinessRisk',
    'EvaluationResult',
    'EvaluationEngine',
    'EvaluationConfig',
    'evaluate_snapshot',
    'prioritize_risk',
    'technical_to_business_risk',
    
    # Alte Klassen für Kompatibilität (deprecated)
    'Evaluation',
    'evaluate_asset_snapshot',
    
    # Alte Konstanten (deprecated)
    'HIGH_RISK_SERVICES',
    'SECURE_INDICATORS', 
    'VULNERABLE_INDICATORS',
]

# Dynamische Exporte der alten Konstanten
HIGH_RISK_SERVICES = _legacy_config.HIGH_RISK_SERVICES
SECURE_INDICATORS = _legacy_config.SECURE_INDICATORS
VULNERABLE_INDICATORS = _legacy_config.VULNERABLE_INDICATORS

# ============================================================================
# NACH OBEN DELEGIEREN
# ============================================================================

def __getattr__(name):
    """
    Forward-Requests für alte Attribute, die nicht mehr direkt existieren.
    """
    # Alte Hilfsfunktionen, die nicht mehr existieren
    if name == '_analyze_open_ports':
        raise AttributeError(
            f"'{name}' wurde entfernt. Verwende die neue EvaluationEngine."
        )
    elif name == '_analyze_services':
        raise AttributeError(
            f"'{name}' wurde entfernt. Verwende die neue EvaluationEngine."
        )
    elif name == '_calculate_risk_level':
        raise AttributeError(
            f"'{name}' wurde entfernt. Verwende RiskPrioritizer oder EvaluationEngine."
        )
    
    raise AttributeError(f"module 'shodan_report.evaluation' has no attribute '{name}'")