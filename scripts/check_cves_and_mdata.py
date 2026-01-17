import json
import sys
from pathlib import Path
from collections import deque

root = Path(__file__).resolve().parents[1]
src_dir = root / 'src'
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

snap_p = Path('snapshots/google/2026-01_8.8.8.8.json')
if not snap_p.exists():
    print('Snapshot missing:', snap_p)
    raise SystemExit(1)

data = json.loads(snap_p.read_text(encoding='utf-8'))

# search for keys mentioning cvE/vuln
keys=set()
q=deque([('',data)])
while q:
    path,obj=q.popleft()
    if isinstance(obj,dict):
        for k,v in obj.items():
            lk=str(k).lower()
            if 'cve' in lk or 'vuln' in lk:
                keys.add(path+'/'+k)
            q.append((path+'/'+k,v))
    elif isinstance(obj,list):
        for i,el in enumerate(obj):
            q.append((f"{path}[{i}]",el))

print('CVE-like keys found:')
for k in sorted(keys):
    print(' -', k)

# Print top-level vulns keys if present
print('\nTop-level vuln keys (top-level):')
for k in ('vulns','vulnerabilities','vulns_list','vulnerabilities_list'):
    if k in data:
        print(f"{k}:", data.get(k))

# Now run prepare_management_data
try:
    from shodan_report.pdf.sections.data.management_data import prepare_management_data
    m = prepare_management_data(data, {})
    print('\nprepare_management_data output:')
    import pprint
    pprint.pprint({
        'total_ports': m.get('total_ports'),
        'cve_count': m.get('cve_count'),
        'unique_cves_sample': m.get('unique_cves')[:20],
        'service_rows_len': len(m.get('service_rows') or []),
    })
except Exception as e:
    print('Error running prepare_management_data:', e)
    raise
