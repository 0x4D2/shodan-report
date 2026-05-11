from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class ReportContext:
    customer_name: str
    month: str
    ip: str
    management_text: str
    trend_text: str
    technical_json: Dict[str, Any]
    evaluation: Dict[str, Any]
    business_risk: str
    config: Optional[Dict[str, Any]] = None
    compare_month: Optional[str] = None
    # Presentation flags
    show_full_cve_list: bool = False
    cve_limit: int = 6
    # Attack Surface Discovery (optional — nur wenn --domain verwendet)
    attack_surface: Optional[Any] = None  # shodan_report.clients.domain_scout.AttackSurface
    # GreyNoise Community (optional — non-fatal, None wenn nicht verfügbar)
    greynoise: Optional[Any] = None  # dict von shodan_report.clients.greynoise.get_greynoise_status
    report_profile: str = "full"
