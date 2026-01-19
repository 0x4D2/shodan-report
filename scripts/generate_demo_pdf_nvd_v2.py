from pathlib import Path
import json
import os

import types
try:
    from shodan_report.pdf.sections.data import cve_enricher as enricher_mod
except Exception:
    # Fallback minimal enricher so demo can run even if module import fails
    enricher_mod = types.SimpleNamespace()
    def _fallback_enrich_cves(ids, technical_json=None, lookup_nvd=False, **kwargs):
        return [
            {
                'id': str(i),
                'nvd_url': f'https://nvd.nist.gov/vuln/detail/{i}',
                'summary': None,
                'cvss': None,
                'ports': [],
            }
            for i in (ids or [])
        ]
    enricher_mod.enrich_cves = _fallback_enrich_cves
    enricher_mod.NvdClient = lambda *a, **k: None


class NvdV2Client:
    BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.api_key = os.environ.get('NVD_API_KEY')

    def _headers(self):
        h = {'User-Agent': 'shodan-report-nvd/1.0'}
        if self.api_key:
            h['apiKey'] = self.api_key
            h['X-Api-Key'] = self.api_key
        return h

    def fetch_cve_json(self, cve_id: str):
        url = f"{self.BASE}?cveId={cve_id}"
        try:
            import requests
            r = requests.get(url, headers=self._headers(), timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
        except Exception:
            # fallback to urllib
            try:
                from urllib.request import Request, urlopen
                req = Request(url, headers=self._headers())
                with urlopen(req, timeout=self.timeout) as resp:
                    data = json.load(resp)
            except Exception:
                return {}

        # Try to normalize NVD v2 shape into legacy-like 'CVE_Items' list
        try:
            vulns = data.get('vulnerabilities') or []
            if isinstance(vulns, list) and len(vulns) > 0:
                v = vulns[0]
            else:
                # older shape
                items = data.get('result', {}).get('CVE_Items') or data.get('CVE_Items') or []
                if items:
                    return {'CVE_Items': items}
                return {}

            # summary extraction
            summary = None
            try:
                summary = v.get('cve', {}).get('descriptions', [])[0].get('value')
            except Exception:
                try:
                    summary = v.get('cve', {}).get('description')
                except Exception:
                    summary = None

            # cvss extraction (robust attempts)
            score = None
            try:
                metrics = v.get('metrics') or v.get('cve', {}).get('metrics') or {}
                # metrics may contain keys like 'cvssMetricV31', 'cvssMetricV3', etc.
                for k, val in (metrics.items() if isinstance(metrics, dict) else []):
                    try:
                        if isinstance(val, list) and len(val) > 0:
                            m0 = val[0]
                            # try common nesting
                            if isinstance(m0, dict):
                                if 'cvssData' in m0 and isinstance(m0.get('cvssData'), dict):
                                    s = m0.get('cvssData', {}).get('baseScore')
                                    if s:
                                        score = float(s)
                                        break
                                if 'cvssV3' in m0 and isinstance(m0.get('cvssV3'), dict):
                                    s = m0.get('cvssV3', {}).get('baseScore')
                                    if s:
                                        score = float(s)
                                        break
                        # sometimes metrics value is a dict with 'baseScore'
                        if isinstance(val, dict) and 'baseScore' in val:
                            score = float(val.get('baseScore'))
                            break
                    except Exception:
                        continue
            except Exception:
                score = None

            # product/vendor guess (try cpes)
            vendor = ''
            product = ''
            try:
                nodes = v.get('cve', {}).get('configurations', []) or v.get('cve', {}).get('vulnerable_configuration', [])
                if isinstance(nodes, list) and nodes:
                    c = None
                    # find first cpe-like string
                    for n in nodes:
                        if isinstance(n, str) and n.startswith('cpe:'):
                            c = n
                            break
                    if not c:
                        # sometimes nodes contain dicts
                        for n in nodes:
                            if isinstance(n, dict):
                                # try to descend
                                for v2 in n.get('nodes', []) or []:
                                    for m in v2.get('cpe_match', []) or []:
                                        c = m.get('cpe23Uri') or m.get('cpe23') or c
                                        if c:
                                            break
                                    if c:
                                        break
                            if c:
                                break
                    if c:
                        parts = c.split(':')
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
            except Exception:
                vendor = ''
                product = ''

            item = {
                'cve': {
                    'CVE_data_meta': {'ID': cve_id},
                    'description': {'description_data': [{'value': summary}]},
                    'affects': {'vendor': {'vendor_data': [{'vendor_name': vendor or '', 'product': {'product_data': [{'product_name': product or ''}]}}]}}
                },
                'impact': {'baseMetricV3': {'cvssV3': {'baseScore': score}}}
            }
            # Keep raw v2 payload for CPE extraction in the enricher
            return {'CVE_Items': [item], 'vulnerabilities': data.get('vulnerabilities')}
        except Exception:
            return {}


def main():
    enricher_mod.NvdClient = lambda: NvdV2Client()

    # ensure cve_overview uses network lookup by replacing its local reference
    import shodan_report.pdf.sections.cve_overview as cov

    def _enrich_with_nvd(ids, technical_json=None, lookup_nvd=False):
        # Toggle live NVD via env: set NVD_LIVE=1 to enable.
        live = os.environ.get("NVD_LIVE") == "1"
        progress = os.environ.get("NVD_PROGRESS") == "1"
        cache_ttl = 0 if os.environ.get("NVD_REFRESH") == "1" else None
        if cache_ttl is None:
            return enricher_mod.enrich_cves(ids, technical_json or {}, lookup_nvd=live, progress=progress)
        return enricher_mod.enrich_cves(ids, technical_json or {}, lookup_nvd=live, progress=progress, cache_ttl=cache_ttl)

    cov.enrich_cves = _enrich_with_nvd

    from shodan_report.pdf.pdf_generator import generate_pdf
    from shodan_report.reporting.management_text import generate_management_text
    from shodan_report.evaluation import Evaluation, RiskLevel, BusinessRisk

    snap = Path('snapshots/CHINANET/2026-01_111.170.152.60.json')
    if not snap.exists():
        print('Snapshot not found:', snap)
        return
    tech = json.loads(snap.read_text(encoding='utf-8'))

    # Demo-only: inject minimal CPE hints so the CVE table can show CPE-derived indicators.
    # This does NOT persist and only affects this demo run. Disabled for live NVD runs.
    def _inject_demo_cpes(data: dict, demo_cves: list) -> None:
        services = data.get("services") or data.get("open_ports") or []
        demo_cves = [str(c) for c in (demo_cves or []) if c]
        cve_idx = 0
        for s in services:
            if not isinstance(s, dict):
                continue
            product = (s.get("product") or s.get("service") or s.get("name") or "").lower()
            if not product:
                continue
            cpes = s.get("cpes") or s.get("cpe") or []
            if cpes:
                continue

            # Map a few known demo products to conservative CPEs
            if "openssh" in product:
                s["cpes"] = ["cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"]
            elif "mysql" in product:
                s["cpes"] = ["cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"]
            elif "clickhouse" in product:
                s["cpes"] = ["cpe:2.3:a:yandex:clickhouse:*:*:*:*:*:*:*:*"]
            elif "http" in product:
                s["cpes"] = ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"]

            # Attach a small subset of CVEs to demonstrate per-service mapping
            if s.get("cpes") and demo_cves:
                take = demo_cves[cve_idx : cve_idx + 2]
                cve_idx += len(take)
                if take:
                    s["vulns"] = take

    if os.environ.get("NVD_LIVE") != "1":
        _inject_demo_cpes(tech, tech.get("vulns") or [])
    ip = tech.get('ip') or 'unknown_ip'
    eval_obj = Evaluation(ip=ip, risk=RiskLevel.CRITICAL, critical_points=[])
    mgmt = generate_management_text(BusinessRisk.CRITICAL, eval_obj, technical_json=tech)
    out = Path('reports/demo/CHINANET_DEMO_NVD')
    out.mkdir(parents=True, exist_ok=True)
    pdf_path = generate_pdf(
        'CHINANET_DEMO_NVD',
        '2026-01',
        ip,
        mgmt,
        '',
        tech,
        {},
        'CRITICAL',
        output_dir=out,
        config={"debug_mdata": False},
    )
    print('Generated demo PDF:', pdf_path)


if __name__ == '__main__':
    main()
