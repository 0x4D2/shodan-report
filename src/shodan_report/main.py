from importlib.resources import files
import os
import json
from dotenv import load_dotenv

from shodan_report.clients.shodan_client import ShodanClient
from shodan_report.parsing.utils import parse_shodan_host
from shodan_report.persistence.snapshot_manager import save_snapshot, load_snapshot, compare_snapshots
from shodan_report.evaluation.evaluation import evaluate_snapshot
from shodan_report.evaluation.risk_prioritization import prioritize_risk
from shodan_report.reporting.management_text import generate_management_text
from shodan_report.reporting.trend import analyze_trend
from shodan_report.reporting.technical_data import build_technical_data

from .pdf.pdf_generator import generate_pdf

def main():
    # Config laden
    load_dotenv()

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise RuntimeError("SHODAN_API_KEY fehlt")
    
    #ip = "217.154.224.104" # my VPS ip
    ip ="111.170.152.60"  # Beispiel IP
    #customer_name ="MG Solutions"
    customer_name ="CHINANET HUBEI PROVINCE NETWORK"

    month ="2025-01"
    prev_month ="2024-12"

    client = ShodanClient(api_key)
    raw_data = client.get_host(ip)
    snapshot = parse_shodan_host(raw_data)

    save_snapshot(snapshot,customer_name, month)

    prev_snapshot = load_snapshot(customer_name, prev_month)

    # Historie / Trend 
    if prev_snapshot:
        changes = compare_snapshots(prev_snapshot, snapshot)
        trend_text = analyze_trend(prev_snapshot, snapshot)
    else:
        changes = None
        trend_text = "Keine historischen Daten für Trendanalyse vorhanden."

    # Bewertung / Priorisierung
    evaluation = evaluate_snapshot(snapshot)
    business_risk = prioritize_risk(evaluation)
    
    # Management Text
    management_text = generate_management_text(business_risk, evaluation) 
  
   # Technischer Anhang vorbereiten (JSON)
    technical_json = build_technical_data(snapshot, prev_snapshot)

    # PDF erstellen (neue Struktur)
    pdf_path = generate_pdf(
        customer_name=customer_name,
        month=month,
        ip=snapshot.ip,
        management_text=management_text,
        trend_text=trend_text,
        technical_json=technical_json
    )

    # Debug 
    print("Bewertung:")
    print(f"IP: {evaluation.ip}")
    print(f"Technisches Risiko: {evaluation.risk.value}")
    print(f"Business-Risiko: {business_risk.value}")
    print("Kritische Punkte:")
    for point in evaluation.critical_points:
        print("-", point)
    print("\nManagement-Zusammenfassung:")
    print(management_text)
    print(f"\nPDF erstellt unter: {pdf_path}")
    print("\n=== Technischer Anhang (JSON) ===")
    print(json.dumps(technical_json, indent=2))

if __name__ == "__main__":
    main()