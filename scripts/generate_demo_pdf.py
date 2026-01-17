from pathlib import Path
import json
from shodan_report.pdf.pdf_generator import generate_pdf
from shodan_report.reporting.management_text import generate_management_text
from shodan_report.evaluation import Evaluation, RiskLevel, BusinessRisk

snap=Path('snapshots/CHINANET/2026-01_111.170_152.60.json')
# Fallback: try the correct path if typo
if not snap.exists():
    snap=Path('snapshots/CHINANET/2026-01_111.170.152.60.json')
if not snap.exists():
    print('Snapshot not found:', snap)
    raise SystemExit(2)
tech=json.loads(snap.read_text(encoding='utf-8'))
ip=tech.get('ip') or 'unknown_ip'
eval_obj=Evaluation(ip=ip, risk=RiskLevel.CRITICAL, critical_points=[])
mgmt=generate_management_text(BusinessRisk.CRITICAL, eval_obj, technical_json=tech)
out=Path('reports/demo/CHINANET_DEMO')
out.mkdir(parents=True, exist_ok=True)
pdf_path=generate_pdf('CHINANET_DEMO','2026-01',ip,mgmt,'',tech,{},'CRITICAL', output_dir=out)
print('PDF_CREATED', pdf_path)
