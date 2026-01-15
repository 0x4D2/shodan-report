import sys
from pathlib import Path
root = Path(__file__).resolve().parents[1]
src_dir = root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from shodan_report.clients.shodan_client import ShodanClient
from shodan_report.parsing.utils import parse_shodan_host
from shodan_report.evaluation import EvaluationEngine
from shodan_report.evaluation.risk_prioritization import prioritize_risk
from shodan_report.reporting.technical_data import build_technical_data
from shodan_report.pdf.sections.data.management_data import prepare_management_data

API_KEY = None
import os
API_KEY = os.getenv('SHODAN_API_KEY')
if not API_KEY:
    print('SHODAN_API_KEY not set; cannot fetch live data.')
    sys.exit(1)

ip = '111.170.152.60'
client = ShodanClient(API_KEY)
raw = client.get_host(ip)
snap = parse_shodan_host(raw)
print('Parsed snapshot services count:', len(getattr(snap, 'services', [])))

prev = None
tech = build_technical_data(snap, prev)
print('Technical open_ports:', len(tech.get('open_ports', [])))

engine = EvaluationEngine()
eval_res = engine.evaluate(snap)
print('Evaluation critical_points:', getattr(eval_res, 'critical_points', []))

mdata = prepare_management_data(tech, eval_res)
print('mdata cve_count:', mdata.get('cve_count'))
print('unique_cves sample (first 20):', mdata.get('unique_cves')[:20])
print('per_service counts:')
for s in mdata.get('per_service', []):
    print(' ', s.get('port'), s.get('product'), s.get('cve_count'), s.get('high_cvss'))

print('Done')
