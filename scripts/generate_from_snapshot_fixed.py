import sys
from pathlib import Path
import json

# ensure package import works when running script from repo root
root = Path(__file__).resolve().parents[1]
src_dir = root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from shodan_report.pdf.pdf_generator import generate_pdf

snap = Path('snapshots/CHINANET/2026-01_111.170.152.60.json')
if not snap.exists():
    print('Snapshot not found:', snap)
    raise SystemExit(1)

technical_json = json.loads(snap.read_text(encoding='utf-8'))

customer='CHINANET'
month='2026-01-fixed'
ip=technical_json.get('ip','unknown')
management_text='Automatisch generierter Bericht (Snapshot) - fixed'
trend_text='Keine historischen Daten.'

out = generate_pdf(customer_name=customer, month=month, ip=ip, management_text=management_text, trend_text=trend_text, technical_json=technical_json, evaluation={}, business_risk='high', output_dir=Path('reports/demo/CHINANET'))
print('Wrote PDF:', out)
