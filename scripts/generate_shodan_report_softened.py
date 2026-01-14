"""
Generate a softened management text report from pasted Shodan-like output and render a PDF.
"""
from pathlib import Path
import sys
import re

repo = Path(__file__).resolve().parents[1]
src = repo / 'src'
if str(src) not in sys.path:
    sys.path.insert(0, str(src))

from shodan_report.pdf.pdf_generator import generate_pdf

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


def parse_shodan_text(text):
    services = []
    for m in re.finditer(r"(\d+)\s*/\s*tcp\s*\n([\s\S]*?)(?=\n\d+\s*/\s*tcp|$)", text):
        port = int(m.group(1))
        body = m.group(2).strip()
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
    return {'ip': '85.215.121.78', 'services': services}


def build_soft_management_text(parsed):
    services = parsed['services']
    total_ports = len(services)

    # Simple soft phrasing
    lines = []
    lines.append('Auf Basis passiver OSINT-Daten wurden {} öffentlich erreichbare Dienste identifiziert.'.format(total_ports))
    lines.append('Aktuell wurden keine kritisch ausnutzbaren Schwachstellen mit bekannter aktiver Exploit-Verfügbarkeit festgestellt.')

    # If services contain repeated nginx or Plesk, report as security flags (soft)
    prod_counts = {}
    for s in services:
        prod = s.get('product') or 'unknown'
        prod_counts[prod] = prod_counts.get(prod, 0) + 1

    flags = []
    if prod_counts.get('nginx', 0) > 1:
        flags.append(f'{prod_counts["nginx"]} Dienste mit nginx-Konfigurationen, bitte Konfiguration prüfen')
    if 'Plesk' in prod_counts:
        flags.append('Administrative Plesk-Oberfläche erkannt – bitte Zugangskontrollen prüfen')

    # Compose management paragraph with softened tone
    m = []
    m.append('\n'.join(lines))
    if flags:
        m.append('\n'.join(['Erkannte Hinweise:'] + ['- ' + f for f in flags]))
    m.append('Empfehlung: Priorisierte Überprüfung und ggf. Härtungsmaßnahmen planen; keine akute Incident-Response-Maßnahme ersichtlich.')

    return '\n\n'.join(m)


if __name__ == '__main__':
    parsed = parse_shodan_text(SHODAN_INPUT)
    management_text = build_soft_management_text(parsed)

    technical_json = {'open_ports': [{'port': s['port'], 'product': s['product'], 'version': s['version']} for s in parsed['services']], 'vulns': []}
    # Conservative exposure scoring aligned with central EvaluationEngine thresholds
    num_ports = len(parsed['services'])
    if num_ports > 50:
        exposure_score = 5
    elif num_ports > 30:
        exposure_score = 4
    elif num_ports > 20:
        exposure_score = 3
    elif num_ports > 10:
        exposure_score = 2
    else:
        exposure_score = 1

    evaluation = {
        'ip': parsed['ip'],
        'risk': 'HIGH',
        'critical_points': [],
        'exposure_score': exposure_score,
        'exposure_level': f"{exposure_score}/5",
    }

    out = generate_pdf(
        customer_name='berufskollegs-lippe.de',
        month='2026-01',
        ip=parsed['ip'],
        management_text=management_text,
        trend_text='Letzte Sichtung: 2026-01-12',
        technical_json=technical_json,
        evaluation=evaluation,
        business_risk='HIGH',
        output_dir=Path('reports/smoke_soft')
    )
    print('Softened PDF created:', out)
