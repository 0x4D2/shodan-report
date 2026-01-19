"""Minimal CIRCL CVE client wrapper.

Uses https://cve.circl.lu API to fetch CVE details and returns a small NVD-like dict.
"""
from typing import Optional, Dict, Any
import json

try:
    import requests
except Exception:
    requests = None

BASE = "https://cve.circl.lu/api/cve/"


class CirclClient:
    def __init__(self, user_agent: str = 'shodan-report-circl/1.0', timeout: int = 15):
        self.user_agent = user_agent
        self.timeout = timeout

    def fetch_cve_json(self, cve_id: str) -> Optional[Dict[str, Any]]:
        url = BASE + cve_id
        headers = {'User-Agent': self.user_agent}
        try:
            if requests:
                r = requests.get(url, headers=headers, timeout=self.timeout)
                r.raise_for_status()
                data = r.json()
            else:
                from urllib.request import Request, urlopen
                req = Request(url, headers=headers)
                with urlopen(req, timeout=self.timeout) as resp:
                    data = json.load(resp)
        except Exception:
            return None

        # Convert CIRCL shape to NVD-like minimal structure the enricher expects
        try:
            desc = data.get('summary') or None
        except Exception:
            desc = None

        score = None
        try:
            # CIRCL may provide cvss score under 'cvss' or 'cvss3'
            if 'cvss' in data and data.get('cvss'):
                score = float(data.get('cvss'))
        except Exception:
            score = None

        vendor = None
        product = None
        try:
            nodes = data.get('vulnerable_configuration') or []
            if isinstance(nodes, list) and nodes:
                # nodes are cpe URIs; try parse first
                c = nodes[0]
                parts = c.split(':')
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
        except Exception:
            vendor = None
            product = None

        item = {
            'CVE_Items': [
                {
                    'cve': {
                        'CVE_data_meta': {'ID': cve_id},
                        'description': {'description_data': [{'value': desc}]},
                        'affects': {
                            'vendor': {
                                'vendor_data': [
                                    {
                                        'vendor_name': vendor or '',
                                        'product': {'product_data': [{'product_name': product or ''}]},
                                    }
                                ]
                            }
                        },
                    },
                    'impact': {'baseMetricV3': {'cvssV3': {'baseScore': score}}},
                }
            ]
        }
        return item
