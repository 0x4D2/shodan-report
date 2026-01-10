import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Any
from pathlib import Path

@dataclass
class RiskWeights:
    # Port Exposure
    open_ports: Dict[str, Any] = field(default_factory=lambda: {
        "thresholds": [15, 20, 30],
        "scores": [0, 1, 2, 3]
    })
    
    # High-risk services
    high_risk_services: Dict[str, int] = field(default_factory=lambda: {
        "rdp_unencrypted": 5,
        "vnc_unencrypted": 5,
        "telnet": 4,
        "database_unencrypted": 4,
        "ftp_unencrypted": 2,
        "ssh_old_version": 2
    })
    
    # Server profiles
    server_profiles: Dict[str, Any] = field(default_factory=lambda: {
        "web_server": {
            "expected_ports": [80, 443],
            "bonus_ports": [8080, 8443],
            "min_ports_for_detection": 1
        },
        "mail_server": {
            "expected_ports": [25, 110, 143, 465, 587, 993, 995],
            "min_ports_for_detection": 2
        }
    })
    
    # Version patterns
    vulnerable_indicators: Dict[str, int] = field(default_factory=lambda: {
        "1.0": 2, "2.0": 1, "deprecated": 3, "end-of-life": 4,
        "test": 2, "dev": 2, "alpha": 2, "beta": 1, "rc": 1
    })
    
    # Secure indicators
    secure_indicators: List[str] = field(default_factory=lambda: [
        "tls", "ssl", "starttls", "https", "wss"
    ])

class EvaluationConfig:
    def __init__(self, config_path: str = None):
        self.weights = RiskWeights()
        
        if config_path and Path(config_path).exists():
            self.load_config(config_path)
    
    def load_config(self, path: str):
        with open(path, 'r') as f:
            config_data = yaml.safe_load(f)
            
            # Merge with defaults
            if "risk_weights" in config_data:
                if "open_ports" in config_data["risk_weights"]:
                    self.weights.open_ports.update(config_data["risk_weights"]["open_ports"])
                if "high_risk_services" in config_data["risk_weights"]:
                    self.weights.high_risk_services.update(
                        config_data["risk_weights"]["high_risk_services"]
                    )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_weights": {
                "open_ports": self.weights.open_ports,
                "high_risk_services": self.weights.high_risk_services
            }
        }