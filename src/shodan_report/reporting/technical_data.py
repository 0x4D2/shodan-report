from typing import Optional, Dict, Any
from shodan_report.models import AssetSnapshot
from shodan_report.reporting.trend import analyze_trend


def build_technical_data(
    snapshot: AssetSnapshot, prev_snapshot: Optional[AssetSnapshot] = None
) -> Dict[str, Any]:

    technical = {
        "ip": snapshot.ip,
        "snapshot_date": (
            snapshot.last_update.strftime("%Y-%m-%d") if snapshot.last_update else None
        ),
        "open_ports": [],
        "domains": getattr(snapshot, "domains", []),
        "hostnames": getattr(snapshot, "hostnames", []),
        "org": getattr(snapshot, "org", ""),
        "isp": getattr(snapshot, "isp", ""),
        "country": getattr(snapshot, "country", ""),
        "city": getattr(snapshot, "city", ""),
        "vulnerabilities": getattr(snapshot, "vulns", []),
        "trend": None,
    }

    # Optionale Felder
    if hasattr(snapshot, "asn") and snapshot.asn:
        technical["asn"] = snapshot.asn
    if hasattr(snapshot, "latitude") and snapshot.latitude:
        technical["latitude"] = snapshot.latitude
    if hasattr(snapshot, "longitude") and snapshot.longitude:
        technical["longitude"] = snapshot.longitude

    # Open Ports mit VOLLSTÄNDIGEN Informationen
    for service in snapshot.services:
        # Daten aus dem erweiterten raw-Dict extrahieren

        raw = getattr(service, "raw", None)
        if raw is None:
            parsed_data = ""
            extra_info = ""
            cert_info = ""
        else:
            parsed_data = raw.get("_parsed_data", "")
            extra_info = raw.get("_extra_info", "")
            cert_info = raw.get("_certificate_info", "")

        port_info = {
            "port": service.port,
            "transport": getattr(service, "transport", "tcp"),
            "service": {
                "product": service.product or "Unbekannter Dienst",
                "version": service.version or "",
                "banner": parsed_data,  # Aus raw geholt
            },
            "vulnerabilities": getattr(service, "vulnerabilities", []) or [],
            "extra_info": extra_info,  # Aus raw geholt
            "is_ssl": bool(getattr(service, "ssl_info", None)),
            "is_ssh": bool(getattr(service, "ssh_info", None)),
        }

        port_info["service_type"] = _classify_service_type(service)

        technical["open_ports"].append(port_info)

    # Kritische Services identifizieren (für spätere Analyse)
    technical["critical_services"] = _identify_critical_services(
        technical["open_ports"]
    )
    technical["vulnerable_versions"] = _identify_vulnerable_versions(
        technical["open_ports"]
    )

    # Trend-Analyse (falls Vergleichssnapshot)
    if prev_snapshot:
        technical["trend"] = analyze_trend(prev_snapshot, snapshot)

    return technical


def _classify_service_type(service) -> str:
    """Klassifiziere den Service-Typ für bessere Analyse."""
    port = service.port

    # Bekannte Port-Kategorien
    if port == 53:
        return "dns"
    elif port in [80, 443, 8080, 8443]:
        return "web"
    elif port == 22:
        return "ssh"
    elif port in [21, 20]:
        return "ftp"
    elif port == 23:
        return "telnet"
    elif port == 25:
        return "smtp"
    elif port in [3306, 5432, 27017, 1433]:
        return "database"
    elif port in [137, 138, 139, 445]:
        return "fileshare"
    else:
        return "other"


def _identify_critical_services(open_ports: list) -> list:
    critical = []

    for port_info in open_ports:
        port = port_info["port"]
        extra_info = port_info.get("extra_info", "").lower()

        # DNS mit Recursion ist kritisch
        if port == 53 and "recursion enabled" in extra_info:
            critical.append(
                {
                    "port": port,
                    "reason": "DNS Recursion aktiv - Kann für Amplification-Angriffe genutzt werden",
                    "severity": "high",
                }
            )

        # SSH ohne spezielle Info (oft schlecht konfiguriert)
        elif port == 22 and not port_info.get("is_ssl", False):
            critical.append(
                {
                    "port": port,
                    "reason": "SSH Service öffentlich erreichbar - Prüfe auf starke Authentifizierung",
                    "severity": "medium",
                }
            )

        elif port in [3306, 5432, 27017, 1433]:
            critical.append(
                {
                    "port": port,
                    "reason": f"Datenbank Service (Port {port}) öffentlich erreichbar",
                    "severity": "high",
                }
            )

    return critical


def _identify_vulnerable_versions(open_ports: list) -> list:
    vulnerable = []

    for port_info in open_ports:
        version = port_info["service"].get("version", "")
        product = port_info["service"].get("product", "").lower()

        # später durch echte CVE-Datenbank ersetzen
        if "old" in version.lower() or "deprecated" in version.lower():
            vulnerable.append(
                {
                    "port": port_info["port"],
                    "product": product,
                    "version": version,
                    "reason": "Veraltete Version erkannt",
                }
            )
        elif "test" in version.lower() or "dev" in version.lower():
            vulnerable.append(
                {
                    "port": port_info["port"],
                    "product": product,
                    "version": version,
                    "reason": "Entwicklungs-/Testversion",
                }
            )

    return vulnerable
