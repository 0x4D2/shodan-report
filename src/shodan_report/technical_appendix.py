from shodan_report.models import AssetSnapshot
from shodan_report.snapshot_manager import compare_snapshots
from shodan_report.trend import analyze_trend

def generate_technical_appendix(snapshot: AssetSnapshot, prev_snapshot: AssetSnapshot | None = None) -> dict:
    """
    Erstellt den technischen Anhang für einen Snapshot, inklusive Vergleich zum Vormonat.
    """
    appendix = {
        "ip": snapshot.ip,
        "snapshot_date": snapshot.timestamp.isoformat() if hasattr(snapshot, "timestamp") else None,
        "open_ports": [],
        "critical_services": [],
        "vulnerable_versions": [],
        "trend": None
    }

    for service in snapshot.services:
        port_info = {
            "port": service.port,
            "product": service.product or getattr(service, "banner", "unbekannt"),
            "version": service.version or "unbekannt"
        }
        appendix["open_ports"].append(port_info)

        if service.product and service.product.lower() in ["ssh", "rdp"]:
            appendix["critical_services"].append(port_info)

        if service.version and any(ind in service.version.lower() for ind in ["1.0", "vulnerable"]):
            appendix["vulnerable_versions"].append(port_info)

    if prev_snapshot:
        appendix["trend"] = analyze_trend(prev_snapshot, snapshot)

    return appendix
