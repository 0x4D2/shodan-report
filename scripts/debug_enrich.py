import json
import traceback
from pathlib import Path

from shodan_report.pdf.sections.data import cve_enricher as enr


def main():
    snap = Path('snapshots/CHINANET/2026-01_111.170.152.60.json')
    if not snap.exists():
        print('snapshot missing')
        return
    tech = json.loads(snap.read_text(encoding='utf-8'))
    # gather CVE ids (best-effort)
    cve_ids = []
    for s in tech.get('open_ports', []) or tech.get('services', []) or []:
        for v in s.get('vulnerabilities', []) if isinstance(s, dict) else []:
            if isinstance(v, dict) and v.get('id'):
                cve_ids.append(v.get('id'))

    # fallback: include a sample list
    if not cve_ids:
        cve_ids = [
            'CVE-2023-22032',
            'CVE-2023-22059',
            'CVE-2024-20961',
        ]

    try:
        res = enr.enrich_cves(cve_ids, technical_json=tech, lookup_nvd=True)
        print('result type:', type(res))
        if res is None:
            print('enrich_cves returned None')
        else:
            print('len:', len(res))
            print('sample:', res[:3])
    except Exception:
        traceback.print_exc()


if __name__ == '__main__':
    main()
