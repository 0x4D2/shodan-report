from typing import List, Tuple
from shodan_report.models import Service


def analyze_open_ports(services: List[Service]) -> Tuple[int, List[str]]:
    """Pure helper: score open-port surface and return (score, findings)."""
    score = 0
    findings: List[str] = []

    num_ports = len(services)
    # TODO: consider moving these threshold values to `config.weights`
    # (e.g. `weights.port_count.thresholds`) so they are configurable
    # per-customer. Keeping them here for now keeps behaviour stable.
    if num_ports > 25:
        score += 3
        findings.append(f"Sehr viele offene Ports: {num_ports}")
    elif num_ports >= 15:
        score += 2
        findings.append(f"Viele offene Ports: {num_ports}")
    elif num_ports > 8:
        score += 1
        findings.append("Mehrere offene Dienste")

    return score, findings


def analyze_services(services: List[Service]) -> Tuple[int, List[str]]:
    """Pure helper: inspect each service and return (score, findings)."""
    score = 0
    findings: List[str] = []

    for service in services:
        port = service.port
        has_ssl = bool(service.ssl_info)
        product = (service.product or "").lower()
        version = (service.version or "").lower()

        # Kritische Services
        if port == 3389 and not has_ssl:
            findings.append("RDP öffentlich erreichbar ohne Verschlüsselung")
            score += 3
        elif port == 5900 and not has_ssl:
            findings.append("VNC öffentlich erreichbar ohne Verschlüsselung")
            score += 3
        elif port == 23:
            findings.append("Telnet (unverschlüsselt)")
            score += 3

        # SSH als kritischer Dienst
        elif port == 22:
            findings.append("Kritischer Dienst gefunden: SSH")
            score += 2

        # Datenbanken
        elif port in [3306, 5432, 27017, 6379, 1433] and not has_ssl:
            findings.append(f"Datenbank öffentlich erreichbar auf Port {port}")
            score += 2

        # FTP unverschlüsselt
        elif port == 21 and not has_ssl:
            findings.append("FTP unverschlüsselt")
            score += 1

        # HTTP ohne SSL
        elif port == 80 and not has_ssl:
            findings.append("HTTP ohne Verschlüsselung")
            score += 1

        # Veraltete Versionen
        if "1.0" in version or "deprecated" in version:
            findings.append("Veraltete/anfällige Version erkannt")
            score += 1

    return score, findings
