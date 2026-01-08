import os
from dotenv import load_dotenv

from shodan_report.archiver.snapshot_archiver import archive_snapshot as archive_snapshot_legacy
from shodan_report.archiver.report_archiver import ReportArchiver
from shodan_report.clients.shodan_client import ShodanClient
from shodan_report.parsing.utils import parse_shodan_host
from shodan_report.persistence.snapshot_manager import save_snapshot, load_snapshot
from shodan_report.evaluation.evaluation import evaluate_snapshot
from shodan_report.evaluation.risk_prioritization import prioritize_risk
from shodan_report.reporting.management_text import generate_management_text
from shodan_report.reporting.trend import analyze_trend
from shodan_report.reporting.technical_data import build_technical_data
from shodan_report.pdf.pdf_generator import generate_pdf


def main():
    load_dotenv()
    
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        raise RuntimeError("SHODAN_API_KEY fehlt")
    
     #ip = "217.154.224.104" # my VPS ip
    ip ="111.170.152.60"  # Beispiel IP
    #customer_name ="MG Solutions"
    customer_name ="CHINANET HUBEI PROVINCE NETWORK"
    month = "2025-01"
    prev_month = "2024-12"

    # Daten abrufen und parsen
    client = ShodanClient(api_key)
    raw_data = client.get_host(ip)
    snapshot = parse_shodan_host(raw_data)
    
    # Snapshot speichern
    save_snapshot(snapshot, customer_name, month)
    
    # Vorherigen Snapshot laden
    prev_snapshot = load_snapshot(customer_name, prev_month)
    
    # Trend analysieren
    trend_text = analyze_trend(prev_snapshot, snapshot) if prev_snapshot else "Keine historischen Daten für Trendanalyse vorhanden."
    
    # Bewertung
    evaluation = evaluate_snapshot(snapshot)
    business_risk = prioritize_risk(evaluation)
    
    # Management Text
    management_text = generate_management_text(business_risk, evaluation)
    
    # HTML bereinigen
    import re
    management_text = re.sub(r'<[^>]+>', '', management_text)
    
    # Technischer Anhang
    technical_json = build_technical_data(snapshot, prev_snapshot)
    
    # PDF erstellen
    pdf_path = generate_pdf(
        customer_name=customer_name,
        month=month,
        ip=snapshot.ip,
        management_text=management_text,
        trend_text=trend_text,
        technical_json=technical_json
    )
    
    # Alte Archivierung
    # archived_path = archive_snapshot_legacy(snapshot, customer_name, month)
    # print(f"Snapshot archiviert: {archived_path}")
    
    # Neue revisionssichere Archivierung
    report_archiver = ReportArchiver()
    metadata = report_archiver.archive_report(
        pdf_path=pdf_path,
        customer_name=customer_name,
        month=month,
        ip=snapshot.ip
    )
    print(f"Report archiviert (v{metadata['version']}): {metadata['pdf_path']}")
    
    # Zusammenfassung
    print(f"\nPDF erstellt: {pdf_path}")
    print(f"Business-Risiko: {business_risk.value}")


if __name__ == "__main__":
    main()