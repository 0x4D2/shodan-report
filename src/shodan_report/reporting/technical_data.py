from typing import Optional
from shodan_report.models import AssetSnapshot
from shodan_report.reporting.trend import analyze_trend

def build_technical_data(snapshot: AssetSnapshot, prev_snapshot: Optional[AssetSnapshot]=None) -> dict:
    technical = {
        "ip": snapshot.ip,
        "ports": [],
        "vulnerabilities": getattr(snapshot, "vulnerabilities", []),
        "trend": None
    }

    for service in snapshot.services:
        port_info = {
            "port": service.port,
            "product": service.product or getattr(service, "banner", "Unbekannt"),
            "version": service.version or "",
            "service": getattr(service, "service", "")
        }
        technical["ports"].append(port_info)

    if prev_snapshot:
        technical["trend"] = analyze_trend(prev_snapshot, snapshot)

    return technical