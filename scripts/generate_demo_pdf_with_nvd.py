from pathlib import Path
import json

# Prepare dummy NVD and CISA clients and monkeypatch the enricher and overview to use lookup_nvd
from shodan_report.pdf.sections.data import cve_enricher as enricher_mod
from shodan_report.pdf import sections as sections_pkg


class DummyNvd:
    def fetch_cve_json(self, cve_id):
        # Minimal NVD-like payload including product and cvss
        return {
            "result": {
                "CVE_Items": [
                    {
                        "cve": {
                            "CVE_data_meta": {"ID": cve_id},
                            "description": {"description_data": [{"value": f"Summary for {cve_id}"}]},
                            "affects": {
                                "vendor": {
                                    "vendor_data": [
                                        {
                                            "vendor_name": "example-vendor",
                                            "product": {"product_data": [{"product_name": "nginx"}]},
                                        }
                                    ]
                                }
                            },
                        },
                        "impact": {"baseMetricV3": {"cvssV3": {"baseScore": 7.5}}},
                    }
                ]
            }
        }


class DummyCisa:
    def __init__(self, kev=None):
        self._kev = set(kev or [])

    def fetch_kev_set(self):
        return self._kev


def main():
    # attach dummy clients so enrich_cves uses them
    enricher_mod.NvdClient = lambda: DummyNvd()
    enricher_mod.CisaClient = lambda: DummyCisa(kev={"CVE-2023-FOO"})

    # ensure cve_overview uses network lookup by replacing its local reference
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
    out = Path('reports/demo/CHINANET_DEMO')
    out.mkdir(parents=True, exist_ok=True)
    pdf_path = generate_pdf('CHINANET_DEMO', '2026-01', ip, mgmt, '', tech, {}, 'CRITICAL', output_dir=out)
    print('Generated demo PDF:', pdf_path)


if __name__ == '__main__':
    main()
