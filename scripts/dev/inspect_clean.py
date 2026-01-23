import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
src_dir = root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from shodan_report.pdf.sections.data.management_data import prepare_management_data
from shodan_report.pdf.sections.data.technical_data import prepare_technical_detail

snap_path = Path('snapshots/Clean/2026-01_82.100.220.31.json')
snap = json.loads(snap_path.read_text(encoding='utf-8'))

md = prepare_management_data(snap, {})
td = prepare_technical_detail(snap, {})

print('service_rows:')
for r in md.get('service_rows', []):
    print(r)

print('\ntechnical services:')
for s in td.get('services', []):
    print(s.get('port'), s.get('product'), s.get('version'))
