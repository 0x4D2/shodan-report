"""
Generate a PDF report from pasted Shodan-like data for an IP.
Usage: python scripts/generate_report_from_shodan.py
"""
from pathlib import Path
import json
import re
import sys

repo = Path(__file__).resolve().parents[1]
src = repo / 'src'
if str(src) not in sys.path:
    sys.path.insert(0, str(src))

from shodan_report.pdf.pdf_generator import generate_pdf

# Build technical_json from the provided Shodan text (hardcoded here)
SHODAN_TEXT = '''
85.215.121.78
OpenPorts
22
80
443
8443

22 / tcp
OpenSSH9.6p1 Ubuntu 3ubuntu13.14

80 / tcp
nginx

443 / tcp
nginx
Plesk Obsidian 18.0.74

8443 / tcp
Plesk Obsidian 18.0.75

SSL Certificate
Issuer: Plesk
Subject: Plesk
'''

# naive parsing
ports = []
services = []
for m in re.finditer(r"(\d+)\s*/\s*tcp\s*\n([\s\S]*?)(?=\n\d+\s*/\s*tcp|$)", SHODAN_TEXT):
    port = int(m.group(1))
    body = m.group(2).strip()
    ports.append(port)
    prod = None
    version = None
    if 'OpenSSH' in body:
        prod = 'OpenSSH'
        version_match = re.search(r'OpenSSH([\d\.p]+)', body)
        if version_match:
            version = version_match.group(1)
    elif 'nginx' in body.lower():
        prod = 'nginx'
    elif 'Plesk' in body:
        prod = 'Plesk'
    services.append({'port': port, 'product': prod, 'version': version, 'raw': body})

technical_json = {'open_ports': services, 'vulns': []}

evaluation = {'ip': '85.215.121.78', 'risk': 'HIGH', 'critical_points': [], 'cves': []}

out = generate_pdf(
    customer_name='berufskollegs-lippe.de',
    month='2026-01',
    ip='85.215.121.78',
    management_text='Automatisch generierter Management-Text (aus Shodan-Rohdaten).',
    trend_text='Letzte Sichtungen: 2026-01-12',
    technical_json=technical_json,
    evaluation=evaluation,
    business_risk='HIGH',
    output_dir=Path('reports/smoke')
)
print('PDF created:', out)
