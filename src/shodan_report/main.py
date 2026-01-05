from importlib.resources import files
import os

from dotenv import load_dotenv

from shodan_report import evaluation
from shodan_report.shodan_client import ShodanClient
from shodan_report.utils import parse_shodan_host
from shodan_report.evaluation import evaluate_snapshot
from shodan_report.snapshot_manager import save_snapshot, load_snapshot, compare_snapshots
from shodan_report.risk_prioritization import prioritize_risk

def main():
    # Config laden
    load_dotenv()

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise RuntimeError("SHODAN_API_KEY fehlt")
    
    ip = "217.154.224.104" # my VPS ip
    #ip ="111.170.152.60"  # Beispiel IP
    customer_name ="MG Solutions"
   # customer_name ="CHINANET HUBEI PROVINCE NETWORK"

    month ="2025-01"
    prev_month ="2024-12"

    client = ShodanClient(api_key)
    raw_data = client.get_host(ip)
    snapshot = parse_shodan_host(raw_data)

    save_snapshot(snapshot,customer_name, month)

    prev_snapshot = load_snapshot(customer_name, prev_month)

    if prev_snapshot:
        changes = compare_snapshots(prev_snapshot, snapshot)
        print("Änderungen seit Vormonat:")
        print(changes)
    else:
        print("Kein Snapshot vom Vormonat gefunden. Änderungen können nicht berechnet werden.")

    evaluation = evaluate_snapshot(snapshot)
    business_risk = prioritize_risk(evaluation)

    print("Bewertung:")
    print(f"IP: {evaluation.ip}")
    print(f"Technisches Risiko: {evaluation.risk.value}")
    print(f"Business-Risiko: {business_risk.value}")
    print("Kritische Punkte:")
    for point in evaluation.critical_points:
        print("-", point)

if __name__ == "__main__":
    main()