"""CISA KEV (Known Exploited Vulnerabilities) client.

Provides a small helper to fetch and parse the KEV feed.
"""
from typing import Set, Tuple, Dict
import json
import time

try:
    import requests
except Exception:
    requests = None

CISA_KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'


class CisaClient:
    """Client to fetch the CISA KEV feed and return a set of CVE IDs."""

    def __init__(self, user_agent: str = 'shodan-report-cisa-client/1.0', timeout: int = 15):
        self.user_agent = user_agent
        self.timeout = timeout

    def fetch_kev_set(self) -> Set[str]:
        """Fetch KEV feed and return a set of CVE IDs. Returns empty set on error."""
        headers = {'User-Agent': self.user_agent}
        try:
            if requests:
                r = requests.get(CISA_KEV, headers=headers, timeout=self.timeout)
                r.raise_for_status()
                data = r.json()
            else:
                from urllib.request import Request, urlopen
                req = Request(CISA_KEV, headers=headers)
                with urlopen(req, timeout=self.timeout) as resp:
                    data = json.load(resp)
            vulns = data.get('vulnerabilities') or []
            return {v.get('cveID') for v in vulns if v.get('cveID')}
        except Exception:
            return set()
