from pathlib import Path
from shodan_report.core.runner import generate_report_pipeline

jobs_file = Path('jobs.txt')
with jobs_file.open('r', encoding='utf-8') as f:
    for line in f:
        line=line.strip()
        if line and not line.startswith('#'):
            parts=line.split()
            customer = ' '.join(parts[:-2])
            ip = parts[-2]
            month = parts[-1]
            break

print('Running verbose for', customer, ip, month)
res = generate_report_pipeline(customer_name=customer, ip=ip, month=month, archive=False, verbose=True)
print('\nRESULT:', res)
