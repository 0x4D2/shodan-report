import sys
from pathlib import Path
import json
from pprint import pprint

# ensure package import works when running script from repo root
root = Path(__file__).resolve().parents[1]
src_dir = root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from shodan_report.pdf.sections.data.management_data import prepare_management_data
from shodan_report.pdf.sections.data.technical_data import prepare_technical_detail

snap = Path('snapshots/CHINANET/2026-01_111.170.152.60.json')
if not snap.exists():
    print('Snapshot not found:', snap)
    raise SystemExit(1)

technical_json = json.loads(snap.read_text(encoding='utf-8'))

# Evaluation is empty in demo runs earlier; try to import evaluation result if available
evaluation = {}
try:
    # some demo runs may write eval.json besides snapshot
    evalp = snap.parent / (snap.stem + '.eval.json')
    if evalp.exists():
        evaluation = json.loads(evalp.read_text(encoding='utf-8'))
except Exception:
    pass

print('\n== Management Data ==')
mg = prepare_management_data(technical_json, evaluation)
# show critical points sample and counts
pprint({
    'critical_points_count': mg.get('critical_points_count'),
    'critical_points': mg.get('critical_points')[:10],
    'cve_count': mg.get('cve_count'),
    'unique_cves_sample': mg.get('unique_cves')[:10],
})

print('\n== Technical Services (first 10) ==')
tech = prepare_technical_detail(technical_json, evaluation)
services = tech.get('services', [])
for s in services[:10]:
    pprint({
        'port': s.get('port'),
        'product': s.get('product'),
        'version': s.get('version'),
        'server': s.get('server'),
        'banner': (s.get('banner') or '')[:140],
        'cve_count': s.get('cve_count'),
        'high_cvss': s.get('high_cvss'),
    })

print('\n== Technical Meta ==')
print(tech.get('meta'))

print('\nDone.')
