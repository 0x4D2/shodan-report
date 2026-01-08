from datetime import datetime, timezone
from typing import Dict, Any, List

from shodan_report.models import Service, AssetSnapshot

def parse_service(entry: Dict[str, Any]) -> Service:
    import re
    
    product = entry.get("product")
    version = entry.get("version")

    # Shodan Banner auswerten
    banner = entry.get("banner") or entry.get("data")
    
    if banner:
        b = str(banner).strip()
        
        # HTML und CSS entfernen VOR der Verarbeitung
        b = re.sub(r'<[^>]+>', '', b)  # HTML-Tags entfernen
        b = re.sub(r'\{[^}]+\}', '', b)  # CSS entfernen
        b = re.sub(r'\s+', ' ', b)  # Mehrfache Whitespaces reduzieren
        
        parsed_product = None
        parsed_version = None

        if "/" in b:
            parts = b.split("/", 1)
            parsed_product = parts[0] or None
            parsed_version = parts[1] or None
        elif "_" in b:
            parts = b.split("_", 1)
            parsed_product = parts[0] or None
            parsed_version = parts[1] or None
        elif " " in b:
            parts = b.split()
            parsed_product = parts[0] or None
            parsed_version = parts[1] if len(parts) > 1 else None
        else:
            parsed_product = b or None

        if not product:
            product = parsed_product
        if not version:
            version = parsed_version

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

        last_update=datetime.now(timezone.utc)
    )
    return snapshot