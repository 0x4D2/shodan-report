from pathlib import Path
import json
import urllib.request
import urllib.error

from shodan_report.pdf.sections.data import cve_enricher as enricher_mod


class CirclNvd:
    """Minimal wrapper that queries CIRCL CVE API and converts to an NVD-like dict."""

    BASE = "https://cve.circl.lu/api/cve/"

    def fetch_cve_json(self, cve_id: str):
        url = self.BASE + cve_id
        req = urllib.request.Request(url, headers={"User-Agent": "shodan-report-demo/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw)
        except urllib.error.HTTPError as e:
            raise
        except Exception:
            return {}

        # Convert CIRCL shape into a tiny NVD-like structure the enricher expects
        items = []
        try:
            desc = None
            try:
                desc = data.get("containers", {}).get("cna", {}).get("descriptions", [])[0].get("value")
            except Exception:
                desc = None

            # cvss score
            score = None
            try:
                metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
                if metrics and isinstance(metrics, list):
                    m0 = metrics[0]
                    # look for cvssV3_1 or cvssV3
                    if "cvssV3_1" in m0:
                        score = m0["cvssV3_1"].get("baseScore")
                    elif "cvssV3" in m0:
                        score = m0["cvssV3"].get("baseScore")
            except Exception:
                score = None

            # affected products
            vendor = None
            product = None
            try:
                affected = data.get("containers", {}).get("cna", {}).get("affected", [])
                if affected and isinstance(affected, list):
                    a0 = affected[0]
                    vendor = a0.get("vendor") or a0.get("vendor")
                    product = a0.get("product") or a0.get("product")
                    # CIRCL uses 'vendor' and 'product' strings; if product absent, check cpes
                    if not product:
                        cpes = a0.get("cpes") or []
                        if cpes:
                            # try to parse first cpe
                            c = cpes[0]
                            parts = c.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
            except Exception:
                vendor = None
                product = None

            item = {
                "cve": {
                    "CVE_data_meta": {"ID": cve_id},
                    "description": {"description_data": [{"value": desc}]},
                    "affects": {
                        "vendor": {
                            "vendor_data": [
                                {
                                    "vendor_name": vendor or "",
                                    "product": {"product_data": [{"product_name": product or ""}]},
                                }
                            ]
                        }
                    },
                },
                "impact": {"baseMetricV3": {"cvssV3": {"baseScore": score}}},
            }
            items.append(item)
        except Exception:
            pass

        return {"CVE_Items": items}


def main():
    # Monkeypatch enricher to use CIRCL wrapper and real CISA client
    enricher_mod.NvdClient = lambda: CirclNvd()

    # Leave CisaClient to the real implementation so KEV set is fetched live
    # Ensure cve_overview uses network lookup by replacing its local reference
    import shodan_report.pdf.sections.cve_overview as cov

    def _enrich_with_nvd(ids, technical_json=None, lookup_nvd=False):
        return enricher_mod.enrich_cves(ids, technical_json or {}, lookup_nvd=True)

    cov.enrich_cves = _enrich_with_nvd

    # Now call existing demo generator flow
    from shodan_report.pdf.pdf_generator import generate_pdf
    from shodan_report.reporting.management_text import generate_management_text
    from shodan_report.evaluation import Evaluation, RiskLevel, BusinessRisk

    snap = Path('snapshots/CHINANET/2026-01_111.170.152.60.json')
    if not snap.exists():
        print('Snapshot not found:', snap)
        return
    tech = json.loads(snap.read_text(encoding='utf-8'))
    ip = tech.get('ip') or 'unknown_ip'
    eval_obj = Evaluation(ip=ip, risk=RiskLevel.CRITICAL, critical_points=[])
    mgmt = generate_management_text(BusinessRisk.CRITICAL, eval_obj, technical_json=tech)
    out = Path('reports/demo/CHINANET_DEMO_REAL')
    out.mkdir(parents=True, exist_ok=True)
    pdf_path = generate_pdf('CHINANET_DEMO_REAL', '2026-01', ip, mgmt, '', tech, {}, 'CRITICAL', output_dir=out)
    print('Generated demo PDF:', pdf_path)


if __name__ == '__main__':
    main()
