from pathlib import Path
import json
import sys

repo = Path(__file__).resolve().parents[1]
src = repo / 'src'
if str(src) not in sys.path:
    sys.path.insert(0, str(src))

from shodan_report.pdf.pdf_generator import generate_pdf

snap_path = Path('snapshots/CHINANET/2026-01_111.170.152.60.demo.json')
if not snap_path.exists():
    print('Snapshot not found:', snap_path)
    sys.exit(1)

with snap_path.open('r', encoding='utf-8') as fh:
    technical_json = json.load(fh)

# minimal evaluation placeholder
evaluation = {'ip': technical_json.get('ip'), 'risk': 'MEDIUM', 'cves': technical_json.get('vulnerabilities', [])}

out = generate_pdf(
    customer_name='CHINANET',
    month='2026-01',
    ip=technical_json.get('ip'),
    management_text='Demo Management-Text für CHINANET',
    trend_text='Demo-Trend: leichte Zunahme kritischer Dienste',
    technical_json=technical_json,
    evaluation=evaluation,
    business_risk='MEDIUM',
    output_dir=Path('reports/CHINANET'),
    compare_month='Vormonatsanalyse'
)
print('PDF created:', out)
