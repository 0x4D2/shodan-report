# scripts/run-jobs-direct.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from shodan_report.core.runner import generate_report_pipeline

print("=== Batch Processing ===")

# 1. Jobs laden
jobs_file = Path("jobs.txt")
if not jobs_file.exists():
    print("jobs.txt missing")
    sys.exit(1)

jobs = []
with open(jobs_file, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#'):
            jobs.append(line)

total = len(jobs)
success = 0

print(f"Processing {total} jobs...")

# 2. CONFIG MAPPING (Customer → Config-Datei)
config_mapping = {
    "MG_Solutions": "config/customers/mg-solutions.yaml",
    "CHINANET": "config/customers/chinanet-hubei.yaml", 
    "Next_Vision_GmbH": "config/customers/next-vision-gmbh.yaml",
}

for i, line in enumerate(jobs, 1):
    parts = line.split()
    if len(parts) != 3:
        print(f"[{i}] Invalid: {line}")
        continue
    
    customer, ip, month = parts
    print(f"[{i}/{total}] {customer} - {ip} - {month}")
    
    config_path = None
    if customer in config_mapping:
        config_path = Path(config_mapping[customer])
        if not config_path.exists():
            print(f"⚠️  Config nicht gefunden: {config_path}")
            config_path = None
    else:
        print(f"⚠️  Kein Config-Mapping für: {customer}")
    
    # 4. MIT CONFIG AUFRUFEN
    result = generate_report_pipeline(
        customer_name=customer,
        ip=ip,
        month=month,
        config_path=config_path,  
        archive=True,
        compare_month=None,
        verbose=False
    )
    
    if result.get("success"):
        print(f" Success - PDF: {result.get('pdf_path', '?')}")
        success += 1
    else:
        print(f" Failed: {result.get('error', 'Unknown error')}")

print(f"\n=== Done ===")
print(f"{success}/{total} successful")