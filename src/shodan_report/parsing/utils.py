# src/shodan_report/parsing/utils.py
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
import re

from shodan_report.models import Service, AssetSnapshot


def _extract_product_version(entry: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
  
    # 1. Erst aus expliziten Feldern nehmen
    product = entry.get("product")
    version = entry.get("version")
    
    # 2. Falls nicht vorhanden, aus Banner/Data parsen
    banner = entry.get("banner") or entry.get("data", "")
    
    if banner and not (product and version):
        b = str(banner).strip()
        
        # HTML und CSS entfernen
        b = re.sub(r'<[^>]+>', '', b)
        b = re.sub(r'\{[^}]+\}', '', b)
        b = re.sub(r'\s+', ' ', b)
        
        # Produkt/Version aus Banner extrahieren
        parsed_product, parsed_version = None, None
        
        if "/" in b:
            parts = b.split("/", 1)
            parsed_product = parts[0].strip() if parts[0].strip() else None
            parsed_version = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
        elif "_" in b:
            parts = b.split("_", 1)
            parsed_product = parts[0].strip() if parts[0].strip() else None
            parsed_version = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
        elif " " in b:
            parts = b.split()
            parsed_product = parts[0].strip() if parts[0].strip() else None
            parsed_version = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
        else:
            parsed_product = b.strip() if b.strip() else None
        
        if not product and parsed_product:
            product = parsed_product
        if not version and parsed_version:
            version = parsed_version
    
    return product, version


def _extract_service_specific_data(entry: Dict[str, Any]) -> str:
    port = entry.get("port")
    data = entry.get("data", "")
    raw_data = entry  # Das gesamte entry-Dict
    
    if port == 53:
        dns_info = raw_data.get("dns", {})
        if isinstance(dns_info, dict) and dns_info.get("recursive"):
            return "DNS Recursion aktiv"
        
        # Prüfe data/banner Feld
        if "recursion: enabled" in str(data).lower():
            return "DNS Recursion aktiv"
        elif "recursion: disabled" in str(data).lower():
            return "DNS Recursion deaktiviert"
        
        # Prüfe raw banner
        banner = raw_data.get("banner", "")
        if "recursion: enabled" in str(banner).lower():
            return "DNS Recursion aktiv"
    
    # 2. TLS/SSL Information
    elif port == 443:
        ssl_info = raw_data.get("ssl")
        if ssl_info:
            if isinstance(ssl_info, dict):
                cert = ssl_info.get("cert", {})
                if isinstance(cert, dict):
                    subject = cert.get("subject", {})
                    cn = subject.get("CN", "")
                    if cn:
                        return f"TLS Zertifikat: {cn}"
                elif isinstance(cert, str):
                    return f"TLS Zertifikat: {cert[:50]}..."
                return "TLS/SSL aktiv"
            elif isinstance(ssl_info, str):
                return f"TLS: {ssl_info[:50]}..."
            else:
                return "TLS/SSL aktiv"
    
    # 3. SSH Information
    elif port == 22:
        ssh_info = raw_data.get("ssh")
        if ssh_info:
            if isinstance(ssh_info, dict):
                version = ssh_info.get("version", "")
                if version:
                    return f"SSH {version}"
                else:
                    return "SSH Service"
            elif isinstance(ssh_info, str):
                return f"SSH: {ssh_info[:50]}..."
            return "SSH Service"
    
    return ""


def parse_service(entry: Dict[str, Any], host_vulns: List = None) -> Service:
 
    product, version = _extract_product_version(entry)
    
    extra_data = _extract_service_specific_data(entry)
    
    raw_data = entry.get("data", "")
    display_data = raw_data
    service_cves = []
    
    if display_data:
        # Für Anzeige bereinigen (nicht für raw!)
        display_data = str(display_data).strip()
        display_data = re.sub(r'<[^>]+>', '', display_data)
        display_data = re.sub(r'\{[^}]+\}', '', display_data)
        display_data = re.sub(r'\s+', ' ', display_data)
        display_data = display_data[:200] 

    if "vulns" in entry:
        if isinstance(entry["vulns"], list):
            for vuln in entry["vulns"]:
                if isinstance(vuln, dict):
                    service_cves.append(vuln)
                elif isinstance(vuln, str):
                    service_cves.append({"id": vuln})

    if host_vulns and isinstance(host_vulns, list):
        port = entry.get("port")
        product, version = _extract_product_version(entry)
        
        for vuln in host_vulns:
            if isinstance(vuln, dict):
                # Einfache Zuordnung: Wenn Vuln für diesen Port/Product relevant ist
                service_cves.append(vuln)
            elif isinstance(vuln, str):
                service_cves.append({"id": vuln})
    
    enhanced_raw = dict(entry)  

    enhanced_raw["_parsed_data"] = display_data
    enhanced_raw["_extra_info"] = extra_data
    enhanced_raw["_cves"] = service_cves

    # 4. Service-Objekt erstellen
    return Service(
         port=entry.get("port"),
        transport=entry.get("transport", "tcp"),
        product=product,
        version=version,
        ssl_info=entry.get("ssl"),
        ssh_info=entry.get("ssh"),
        raw=enhanced_raw  
    )


def parse_shodan_host(data: Dict[str, Any]) -> AssetSnapshot:

    services: List[Service] = []
    host_vulns = data.get("vulns", []) 
    
    for entry in data.get("data", []):
        if "port" not in entry:
            continue
        
        services.append(parse_service(entry, host_vulns=host_vulns))
    
    location = data.get("location", {})
    
 
    domains = data.get("domains", [])  # Zuerst 'domains' versuchen
    if not domains and "domain" in data:
        # Falls nur 'domain' (Singular) existiert, in Liste umwandeln
        domain_value = data.get("domain")
        if isinstance(domain_value, str):
            domains = [domain_value]
        elif isinstance(domain_value, list):
            domains = domain_value
        else:
            domains = []
    
    return AssetSnapshot(
        ip=data.get("ip_str"),
        hostnames=data.get("hostnames", []),
        domains=domains,  
        
        org=data.get("org", ""),       
        isp=data.get("isp", ""),      
        os=data.get("os"),             
        
        city=location.get("city", ""),      
        country=location.get("country_name", ""), 
        
        services=services,
        open_ports=data.get("ports", []),
        last_update=datetime.now(timezone.utc),
        
        # Optionale Felder
        asn=data.get("asn"),
        latitude=location.get("latitude"),
        longitude=location.get("longitude"),
        vulns=host_vulns
    )


def is_dns_service(service: Service) -> bool:
    return service.port == 53


def is_web_service(service: Service) -> bool:
    return service.port in [80, 443, 8080, 8443]


def is_database_service(service: Service) -> bool:
    return service.port in [3306, 5432, 27017]  # MySQL, PostgreSQL, MongoDB