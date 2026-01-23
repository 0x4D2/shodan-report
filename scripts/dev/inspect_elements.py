import sys
from pathlib import Path
from reportlab.platypus import Paragraph
# ensure package import works when running script from repo root
root = Path(__file__).resolve().parents[1]
src_dir = root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from shodan_report.pdf.pdf_manager import prepare_pdf_elements
import json

snap = Path('snapshots/CHINANET/2026-01_111.170.152.60.json')
technical_json = json.loads(snap.read_text(encoding='utf-8'))

elements = prepare_pdf_elements(
    customer_name='CHINANET',
    month='2026-01',
    ip=technical_json.get('ip','unknown'),
    management_text='demo',
    trend_text='demo',
    technical_json=technical_json,
    evaluation={},
    business_risk='high',
    config={},
)

print('Total elements:', len(elements))
count = 0
for i, el in enumerate(elements):
    t = type(el).__name__
    info = ''
    if isinstance(el, Paragraph):
        try:
            info = el.getPlainText()
        except Exception:
            info = str(el)
    else:
        info = str(el)[:200]
    print(f'{i:03d} {t}: {info}')
    count += 1
    if count > 200:
        break
