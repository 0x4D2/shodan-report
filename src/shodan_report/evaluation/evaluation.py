"""Backward-compatible entrypoint for the evaluation package.

This module re-exports the small, testable modules introduced during
refactor while keeping the original public API intact.
"""
from .core import RiskLevel, BusinessRisk, Evaluation, evaluate_snapshot
from .formatters import prioritize_risk, technical_to_business_risk
from .helpers.eval_helpers import analyze_open_ports as _analyze_open_ports_pure
from .helpers.eval_helpers import analyze_services as _analyze_services_pure


def _analyze_open_ports(services, critical_points):
    score, findings = _analyze_open_ports_pure(services)
    critical_points.extend(findings)
    return score


def _analyze_services(services, critical_points):
    score, findings = _analyze_services_pure(services)
    critical_points.extend(findings)
    return score


# Compatibility constants (kept for public API stability)
HIGH_RISK_SERVICES = {
    "rdp": 5,
    "vnc": 5,
    "telnet": 4,
    "mysql": 4,
    "postgresql": 4,
    "mongodb": 4,
    "redis": 4,
}

SECURE_INDICATORS = ["tls", "ssl", "starttls", "https", "wss"]

VULNERABLE_INDICATORS = {
    "1.0": 2,
    "2.0": 1,
    "deprecated": 3,
    "end-of-life": 4,
    "test": 2,
    "dev": 2,
    "alpha": 2,
    "beta": 1,
    "rc": 1,
}


__all__ = [
    # Enums
    "RiskLevel",
    "BusinessRisk",
    # Classes
    "Evaluation",
    # Main Functions
    "evaluate_snapshot",
    "prioritize_risk",
    "technical_to_business_risk",
    # Helper Functions (for compatibility)
    "_analyze_open_ports",
    "_analyze_services",
    # Constants (for compatibility)
    "HIGH_RISK_SERVICES",
    "SECURE_INDICATORS",
    "VULNERABLE_INDICATORS",
]
