"""
Evaluation Package - Einfache Export-Datei.
"""

# Exportiere alles aus evaluation.py
from .evaluation import (
    Evaluation,
    evaluate_snapshot,
    RiskLevel,
    HIGH_RISK_SERVICES,
    SECURE_INDICATORS,
    VULNERABLE_INDICATORS,
    _analyze_open_ports,
    _analyze_services,
    _calculate_risk_level,
)

# Optional: Exportiere auch BusinessRisk falls benötigt
try:
    from .business_risk import BusinessRisk
    __all__ = [
        'Evaluation',
        'evaluate_snapshot',
        'RiskLevel',
        'BusinessRisk',
        'HIGH_RISK_SERVICES',
        'SECURE_INDICATORS',
        'VULNERABLE_INDICATORS',
        '_analyze_open_ports',
        '_analyze_services',
        '_calculate_risk_level',
    ]
except ImportError:
    __all__ = [
        'Evaluation',
        'evaluate_snapshot',
        'RiskLevel',
        'HIGH_RISK_SERVICES',
        'SECURE_INDICATORS',
        'VULNERABLE_INDICATORS',
        '_analyze_open_ports',
        '_analyze_services',
        '_calculate_risk_level',
    ]