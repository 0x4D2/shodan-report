from pathlib import Path
import sys
root = Path(__file__).resolve().parents[1]
src = root / 'src'
if str(src) not in sys.path:
    sys.path.insert(0, str(src))
from shodan_report.core.runner import generate_report_pipeline

cases = [
    ('Google','8.8.8.8','2026-01'),
    ('MG_Solutions','217.154.224.104','2026-01'),
    ('CHINANET','111.170.152.60','2026-01'),
]
for customer, ip, month in cases:
    print('\n--- Running:', customer, ip, month, 'compare=2025-12')
    res = generate_report_pipeline(customer_name=customer, ip=ip, month=month, compare_month='2025-12', config_path=None, archive=False, verbose=False)
    print('Result:', res)
