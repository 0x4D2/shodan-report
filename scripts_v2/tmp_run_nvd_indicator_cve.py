import json
import sys
from pathlib import Path

# make project root importable
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.shodan_report.clients.nvd_client import NvdClient
from src.shodan_report.clients.helpers.cpe import determine_service_indicator_from_nvd
import re

CVE = 'CVE-2020-0609'

client = NvdClient()

# try JSON
j = client.fetch_cve_json(CVE)
parsed = {}
if j:
    try:
        items = j.get('result', {}).get('CVE_Items') or []
        if items:
            item = items[0]
            # extract cpe_products from configurations
            cfg = item.get('configurations', {})
            prods = set()
            for node in cfg.get('nodes', []) or []:
                for match in node.get('cpe_match', []) or []:
                    uri = match.get('cpe23Uri') or match.get('cpe23uri') or ''
                    parts = uri.split(':')
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        if product:
                            prods.add(product)
                        if vendor:
                            prods.add(vendor)
            parsed['cpe_products'] = list(prods)
            # try CVSS
            impact = item.get('impact', {})
            cvss = None
            if 'baseMetricV3' in impact and impact['baseMetricV3'].get('cvssV3'):
                cvss = impact['baseMetricV3']['cvssV3'].get('baseScore')
            parsed['cvss'] = cvss
    except Exception:
        parsed = {}

# if no JSON CPEs, try HTML fallback
if not parsed.get('cpe_products'):
    status, headers, html = client.fetch_cve_html(CVE)
    if status == 200 and html:
        # extract cpe:2.3 URIs
        cpe_matches = re.findall(r'cpe:2\.3:[^\"\'\s<>\\]+', html, flags=re.IGNORECASE)
        cpe_uris = []
        for uri in cpe_matches:
            u = uri.strip().rstrip('.,;')
            cpe_uris.append(u)
        # also try data-cpe attributes
        data_matches = re.findall(r'data-cpe="([^"]+)"', html)
        for u in data_matches:
            if u and u not in cpe_uris:
                cpe_uris.append(u)
        if cpe_uris:
            parsed['cpe_uris'] = cpe_uris
        # attempt to extract CVSS numeric
        m = re.search(r'CVSS\s*3[\.|\s]*1[^\d]*([0-9]+\.?[0-9]*)', html)
        if not m:
            m = re.search(r'Base Score[^0-9\n]*([0-9]+\.?[0-9]*)', html)
        if m:
            parsed['cvss'] = float(m.group(1))

res = determine_service_indicator_from_nvd(parsed)
print(json.dumps({'cve': CVE, 'nvd_parsed': parsed, 'indicator': res}, indent=2, ensure_ascii=False))
