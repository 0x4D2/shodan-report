from typing import List
from shodan_report.models import Service
from .base import ServiceEvaluator, ServiceRisk

class ServiceEvaluatorRegistry:
    def __init__(self, config):
        self.config = config
        self.evaluators: List[ServiceEvaluator] = self._init_evaluators()
    
    def _init_evaluators(self) -> List[ServiceEvaluator]:
        """Initialisiert alle Evaluatoren in der richtigen Reihenfolge"""
        # Import hier um Zirkuläre Dependencies zu vermeiden
        from .critical_evaluators import RDPEvaluator, VNCEvaluator, TelnetEvaluator
        from .database_evaluators import DatabaseEvaluator
        from .web_evaluators import HTTPSEvaluator
        from .ssh_evaluator import SSHEvaluator
        from .mail_evaluator import MailServiceEvaluator
        from .generic_evaluator import GenericServiceEvaluator
        
        return [
            # Kritische Services zuerst
            RDPEvaluator(self.config),
            VNCEvaluator(self.config),
            TelnetEvaluator(self.config),
            
            # Datenbanken
            DatabaseEvaluator(self.config),
            
            # Web Services
            HTTPSEvaluator(self.config),
            SSHEvaluator(self.config),
            
            # Mail Services
            MailServiceEvaluator(self.config),
            
            # Generischer Fallback
            GenericServiceEvaluator(self.config)
        ]
    
    def evaluate_service(self, service: Service) -> ServiceRisk:
        """Findet und verwendet den passenden Evaluator"""
        for evaluator in self.evaluators:
            if evaluator.applies_to(service):
                return evaluator.evaluate(service)
        return ServiceRisk(risk_score=0)