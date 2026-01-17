"""NVD API client utilities.

Provides a thin, testable wrapper around NVD REST + HTML detail page.

The implementation uses `requests` when available and falls back to
`urllib.request` so the module can be imported in minimal test envs.
"""
from typing import Optional, Tuple, Dict, Any
import os
import json

try:
    import requests
except Exception:  # pragma: no cover - requests optional in test env
    requests = None

NVD_URL = "https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
NVD_HTML = "https://nvd.nist.gov/vuln/detail/{cve_id}"


class NvdClient:
    """Thin client to fetch CVE data from NVD.

    Methods return tuples `(status_code, headers_dict, body_text)` for
    low-level access and convenience helpers to parse JSON when available.
    """

    def __init__(self, api_key: Optional[str] = None, user_agent: Optional[str] = None, timeout: int = 15):
        self.api_key = api_key or os.environ.get('NVD_API_KEY')
        self.user_agent = user_agent or 'shodan-report-nvd-client/1.0'
        self.timeout = timeout
        self._session = requests.Session() if requests else None

    def _default_headers(self) -> Dict[str, str]:
        h = {'User-Agent': self.user_agent}
        if self.api_key:
            h['apiKey'] = self.api_key
        return h

    def fetch_cve(self, cve_id: str) -> Tuple[int, Dict[str, str], str]:
        """Fetch NVD CVE JSON endpoint.

        Returns: `(status_code, headers, body_text)`.
        """
        url = NVD_URL.format(cve_id=cve_id)
        headers = self._default_headers()
        try:
            if requests:
                r = self._session.get(url, headers=headers, timeout=self.timeout)
                return r.status_code, dict(r.headers), r.text
            else:
                from urllib.request import Request, urlopen
                req = Request(url, headers=headers)
                with urlopen(req, timeout=self.timeout) as resp:
                    return resp.getcode(), dict(resp.getheaders()), resp.read().decode('utf-8')
        except Exception as e:
            return getattr(e, 'code', 0) or 0, {}, str(e)

    def fetch_cve_json(self, cve_id: str) -> Optional[Dict[str, Any]]:
        status, headers, body = self.fetch_cve(cve_id)
        if status == 200 and body:
            try:
                return json.loads(body)
            except Exception:
                return None
        return None

    def fetch_cve_html(self, cve_id: str) -> Tuple[int, Dict[str, str], str]:
        """Fetch the NVD CVE detail HTML page (useful as fallback)."""
        url = NVD_HTML.format(cve_id=cve_id)
        headers = {'User-Agent': self.user_agent}
        try:
            if requests:
                r = self._session.get(url, headers=headers, timeout=self.timeout)
                return r.status_code, dict(r.headers), r.text
            else:
                from urllib.request import Request, urlopen
                req = Request(url, headers=headers)
                with urlopen(req, timeout=self.timeout) as resp:
                    return resp.getcode(), dict(resp.getheaders()), resp.read().decode('utf-8')
        except Exception as e:
            return getattr(e, 'code', 0) or 0, {}, str(e)
