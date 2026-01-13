"""
Evaluation Package - Export für die neue Evaluation Engine.
"""

# Exportiere die NEUE Evaluation Engine
from .evaluation_engine import EvaluationEngine, evaluate_snapshot
from .models import EvaluationResult
from .risk_level import RiskLevel

# Exportiere Config
from .config import EvaluationConfig

# Exportiere Business Risk (falls benötigt)
try:
    from .business_risk import BusinessRisk, calculate_business_risk
    BUSINESS_RISK_AVAILABLE = True
except ImportError:
    BUSINESS_RISK_AVAILABLE = False

# Exportiere Risk Prioritization (falls benötigt)
try:
    from .risk_prioritization import RiskPrioritization
    RISK_PRIORITIZATION_AVAILABLE = True
except ImportError:
    RISK_PRIORITIZATION_AVAILABLE = False

# Alte Exports für Backward Compatibility
try:
    from .evaluation import (
        Evaluation as OldEvaluation,
        HIGH_RISK_SERVICES,
        SECURE_INDICATORS,
        VULNERABLE_INDICATORS,
    )
    OLD_EVALUATION_AVAILABLE = True
except ImportError:
    OLD_EVALUATION_AVAILABLE = False

# ─────────────────────────────────────────────
# Haupt-Exports (NEUE ENGINE)
# ─────────────────────────────────────────────
__all__ = [
    'EvaluationEngine',      # ✅ NEU: Haupt-Engine
    'evaluate_snapshot',     # ✅ NEU: Factory-Funktion
    'EvaluationResult',      # ✅ NEU: Ergebnis-Klasse
    'RiskLevel',             # ✅ Risiko-Level Enum
    'EvaluationConfig',      # ✅ Config
]

# ─────────────────────────────────────────────
# Optionale Exports
# ─────────────────────────────────────────────
if BUSINESS_RISK_AVAILABLE:
    __all__.extend(['BusinessRisk', 'calculate_business_risk'])

if RISK_PRIORITIZATION_AVAILABLE:
    __all__.append('RiskPrioritization')

if OLD_EVALUATION_AVAILABLE:
    __all__.extend([
        'Evaluation',           # ⚠️ ALT: Für Backward Compatibility
        'HIGH_RISK_SERVICES',
        'SECURE_INDICATORS', 
        'VULNERABLE_INDICATORS'
    ])


# ─────────────────────────────────────────────
# Hinweis für Migration
# ─────────────────────────────────────────────
__migration_note__ = """
⚠️  MIGRATIONSHINWEIS:
Die alte Evaluation-Klasse ist deprecated. Verwende stattdessen:
from shodan_report.evaluation import EvaluationEngine

Alte Verwendung (deprecated):
from shodan_report.evaluation import Evaluation
result = Evaluation(...)

Neue Verwendung (empfohlen):
from shodan_report.evaluation import EvaluationEngine
engine = EvaluationEngine()
result = engine.evaluate(snapshot)
"""