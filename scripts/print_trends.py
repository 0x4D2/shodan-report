from pathlib import Path
import sys
root = Path(__file__).resolve().parents[1]
src = root / 'src'
if str(src) not in sys.path:
    sys.path.insert(0, str(src))

from shodan_report.persistence.snapshot_manager import load_snapshot
from shodan_report.reporting.trend import analyze_trend

cases = [
    ('Google','8.8.8.8'),
    ('MG_Solutions','217.154.224.104'),
    ('CHINANET','111.170.152.60'),
]
for customer, ip in cases:
    prev = load_snapshot(customer, '2025-12')
    curr = load_snapshot(customer, '2026-01')
    print('\n===', customer, ip, '===')
    if not prev or not curr:
        print('Missing snapshots for', customer)
        continue
    text = analyze_trend(prev, curr)
    print(text)
