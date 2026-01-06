from datetime import datetime
from typing import Dict, Any, List

from shodan_report.models import Service, AssetSnapshot

def parse_service(entry: Dict[str, Any]) -> Service:

    product = entry.get("product")
    version = entry.get("version")

    # Shodan Banner auswerten
    banner = entry.get("banner") or entry.get("data")  # fallback, falls 'banner' nicht vorhanden
    if not product and banner:
        product = banner.split()[0] 
    if not version and banner:
        version = banner.split()[1] if len(banner.split()) > 1 else None

    return Service(
        port=entry.get("port"),
        transport=entry.get("transport"),
        product=product,
        version=version,
        ssl_info=entry.get("ssl"),
        ssh_info=entry.get("ssh"),
        raw=entry
    )

def parse_shodan_host(data: Dict[str, Any]) -> AssetSnapshot:
    services: List[Service] =[]

    for entry in data.get("data", []):
        if "port" not in entry:
            continue

        services.append(parse_service(entry))

    snapshot = AssetSnapshot(
        ip=data.get("ip_str"),
        hostnames=data.get("hostnames", []),
        domains=data.get("domain",[]),

        org=data.get("org"),
        isp=data.get("isp"),
        os=data.get("os"),

        city=(data.get("location") or {}).get("city"),
        country=(data.get("location") or {}).get("country_name"),
        
        services=services,
        open_ports=data.get("ports", []),

        last_update=datetime.utcnow()
    )
    return snapshot