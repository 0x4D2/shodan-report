from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import ServiceEvaluator, ServiceRisk
    from .critical_evaluators import (
        RDPEvaluator, VNCEvaluator, TelnetEvaluator
    )
    from .web_evaluators import HTTPSEvaluator
    from .database_evaluators import DatabaseEvaluator
    from .ssh_evaluator import SSHEvaluator
    from .mail_evaluator import MailServiceEvaluator
    from .generic_evaluator import GenericServiceEvaluator

# Lazy imports vermeiden Zirkuläre Dependencies
__all__ = [
    'ServiceEvaluator',
    'ServiceRisk',
    'RDPEvaluator',
    'VNCEvaluator',
    'TelnetEvaluator',
    'HTTPSEvaluator',
    'DatabaseEvaluator',
    'SSHEvaluator',
    'MailServiceEvaluator',
    'GenericServiceEvaluator'
]