from typing import Optional
from shodan_report.models import AssetSnapshot
from shodan_report.reporting.trend import analyze_trend

def build_technical_data(snapshot: AssetSnapshot, prev_snapshot: Optional[AssetSnapshot]=None) -> dict:
    technical = {
        "ip": snapshot.ip,
        "snapshot_date": snapshot.last_update.strftime("%Y-%m-%d") if snapshot.last_update else None,
        "open_ports": [],
        "vulnerabilities": getattr(snapshot, "vulnerabilities", []),
        "critical_services": [],  # Placeholder 
        "vulnerable_versions": [],  # Placeholder
        "trend": None
    }

    for service in snapshot.services:
        port_info = {
            "port": service.port,
            "service": {
                "product": service.product or getattr(service, "banner", "Unbekannt"),
                "version": service.version or ""
            }
        }
        technical["open_ports"].append(port_info)

    if prev_snapshot:
        technical["trend"] = analyze_trend(prev_snapshot, snapshot)

    return technical