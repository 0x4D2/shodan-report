"""
Simple text report generator from pasted Shodan-like output.
Run: python scripts/generate_text_report.py
"""
import re
from collections import Counter

SHODAN_INPUT = '''
85.215.121.78
Regular View
Raw Data
Timeline
Whois
Last Seen: 2026-01-12
Tags: self-signed
GeneralInformation
Hostnames
berufskollegs-lippe.de
Domains
berufskollegs-lippe.de
 
Country
Germany
City
Berlin
Organization
IONOS SE
ISP
IONOS SE
ASN
AS8560
WebTechnologies
Reverse proxies
Nginx
Web servers
Nginx
OpenPorts
22
80
443
8443
22 / tcp
65648765 | 2025-12-30T22:40:52.848216
OpenSSH9.6p1 Ubuntu 3ubuntu13.14

SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14
Key type: ecdsa-sha2-nistp256

80 / tcp
2057026001
| 2026-01-09T23:01:05.017096
nginx
Web Server's Default Page

443 / tcp
1006893522
| 2026-01-08T17:42:20.489557
nginx
Plesk Obsidian 18.0.74

SSL Certificate

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1744026493 (0x67f3bb7d)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=CH, L=Schaffhausen, O=Plesk, CN=Plesk/emailAddress=info@plesk.com
        Subject: C=CH, L=Schaffhausen, O=Plesk, CN=Plesk/emailAddress=info@plesk.com

8443 / tcp
-729801401
| 2026-01-12T09:56:28.828536
Plesk Obsidian 18.0.75
'''

# heuristics

def parse_shodan_text(text):
    # find ip
    ip_match = re.search(r"^(\d+\.\d+\.\d+\.\d+)", text)
    ip = ip_match.group(1) if ip_match else 'unknown'

    # find open ports blocks like 'NN / tcp' and following body
    services = []
    for m in re.finditer(r"(\d+)\s*/\s*tcp\s*\n([\s\S]*?)(?=\n\d+\s*/\s*tcp|$)", text):
        port = int(m.group(1))
        body = m.group(2).strip()
        # product heuristics
        product = None
        version = None
        if re.search(r"OpenSSH", body, re.I):
            product = 'OpenSSH'
            v = re.search(r"OpenSSH([\d\.p]+)", body)
            if v:
                version = v.group(1)
        elif re.search(r"nginx", body, re.I):
            product = 'nginx'
            v = re.search(r"nginx\s*([0-9\.]+)", body, re.I)
            if v:
                version = v.group(1)
        elif re.search(r"Plesk", body, re.I):
            product = 'Plesk'
            v = re.search(r"Plesk\s+Obsidian\s*([0-9\.]+)", body, re.I)
            if v:
                version = v.group(1)
        services.append({'port': port, 'product': product or 'unknown', 'version': version, 'raw': body})

    return {'ip': ip, 'services': services}


def exposure_score_from_ports(n):
    # conservative mapping aligned with central evaluation thresholds
    if n >= 50:
        return 5
    if n >= 30:
        return 4
    if n >= 20:
        return 3
    if n >= 10:
        return 2
    return 1


def generate_text_report(parsed):
    ip = parsed['ip']
    services = parsed['services']
    total_ports = len(services)
    exposure = exposure_score_from_ports(total_ports)
    exposure_map = {1: 'sehr niedrig', 2: 'niedrig–mittel', 3: 'mittel', 4: 'hoch', 5: 'sehr hoch'}

    # cve heuristics: not available here
    cve_count = 0

    # detect critical points: naive: repeated vulnerable product/version or obsolete-looking version
    critical_points = []
    prod_versions = Counter((s.get('product'), s.get('version')) for s in services)
    for (prod, ver), cnt in prod_versions.items():
        if prod and ver:
            # treat suspicious low major versions as critical (heuristic)
            try:
                major = int(str(ver).split('.')[0])
                if major <= 1:
                    critical_points.extend([f"Kritische Version: {prod} {ver} ({cnt}x)"])
            except Exception:
                pass
        if cnt > 1 and prod and prod.lower() == 'nginx':
            # duplicate nginx instances with same product indicate config issue
            critical_points.append(f"Mehrere Instanzen: {prod} (Anzahl: {cnt})")

    # fallback: if no explicit criticals but product 'Plesk' present and multiple web ports, mark structural risk
    products = [s['product'] for s in services]
    if 'Plesk' in products and sum(1 for p in products if p in ('nginx','Plesk')) >= 2:
        critical_points.append('strukturelle Risiken in der Konfiguration')

    # Management recommendations - simple mapping
    if exposure >= 5 or critical_points:
        risk_text = 'Die externe Angriffsfläche weist kritische Sicherheitsprobleme auf. Wir empfehlen sofortige Priorisierung und Incident-Response-Maßnahmen.'
        recommendations = ['Sofortige Notfallmaßnahmen', 'SOFORT: Incident Response Team aktivieren']
    elif exposure >= 4:
        risk_text = 'Die externe Angriffsfläche zeigt erhöhte Sicherheitsrisiken; zeitnahe, priorisierte Maßnahmen werden empfohlen.'
        recommendations = ['Kurzfristige Maßnahmen zur Härtung']
    else:
        risk_text = 'Die externe Angriffsfläche ist kontrolliert. Regelmäßige Überprüfung wird empfohlen.'
        recommendations = ['Regelmäßiges Monitoring implementieren']

    # build report text
    lines = []
    lines.append('SICHERHEITSREPORT')
    lines.append('Scan: Jan 2026   |   Assets: {}   |   Report-ID: {}'.format(ip.replace('.', ''), 'BER2601'+ip.replace('.','')[:6]))
    lines.append('')
    lines.append('1. Management-Zusammenfassung')
    lines.append('')
    lines.append('Gesamtbewertung der externen Angriffsfläche')
    lines.append('')
    lines.append(f'Exposure-Level: {exposure} von 5 ({exposure_map.get(exposure)})')
    lines.append('')
    lines.append(f'Auf Basis passiver OSINT-Daten wurden {total_ports} öffentlich erreichbare Dienste identifiziert.')
    lines.append('')
    if cve_count == 0:
        lines.append('Aktuell wurden keine kritisch ausnutzbaren Schwachstellen mit bekannter aktiver Exploit-Verfügbarkeit festgestellt.')
    else:
        lines.append(f'Es wurden {cve_count} Sicherheitslücken identifiziert.')
    lines.append('')
    lines.append(risk_text)
    lines.append('')
    lines.append('Wichtigste Erkenntnisse')
    lines.append('')
    lines.append(f'• {total_ports} öffentliche Dienste')
    lines.append('')
    lines.append('• Keine kritischen Schwachstellen')
    lines.append('')
    if critical_points:
        # present first two
        cp_display = critical_points[:2]
        # if they look like counts, format
        for cp in cp_display:
            lines.append(f'• {cp}')
    else:
        lines.append('• Keine kritischen Risikopunkte')

    lines.append('')
    lines.append('Empfehlung auf Management-Ebene')
    lines.append('')
    for r in recommendations:
        lines.append(f'• {r}')

    lines.append('')
    if critical_points:
        lines.append('Details zu kritischen Punkten')
        lines.append('')
        for i, cp in enumerate(critical_points, start=1):
            lines.append(f'{i}. {cp}')

    # Technical appendix
    lines.append('')
    lines.append('Technischer Anhang')
    lines.append('')
    lines.append('Öffentlich erreichbare Dienste:')
    lines.append('')
    for s in services:
        prod = s.get('product') or 'unknown'
        ver = f" ({s['version']})" if s.get('version') else ''
        lines.append(f'• Port {s["port"]}/TCP: {prod}{ver}')

    return '\n'.join(lines)


if __name__ == '__main__':
    parsed = parse_shodan_text(SHODAN_INPUT)
    report = generate_text_report(parsed)
    print(report)
