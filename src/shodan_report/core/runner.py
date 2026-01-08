"""Report Pipeline Runner."""
import os
from pathlib import Path
from typing import Dict, Any, Optional
import re
import yaml

from dotenv import load_dotenv

from shodan_report.clients.shodan_client import ShodanClient
from shodan_report.parsing.utils import parse_shodan_host
from shodan_report.persistence.snapshot_manager import save_snapshot, load_snapshot
from shodan_report.evaluation.evaluation import evaluate_snapshot
from shodan_report.evaluation.risk_prioritization import prioritize_risk
from shodan_report.reporting.management_text import generate_management_text
from shodan_report.reporting.trend import analyze_trend
from shodan_report.reporting.technical_data import build_technical_data
from shodan_report.pdf.pdf_generator import generate_pdf
from shodan_report.archiver.report_archiver import ReportArchiver

def load_customer_config(config_path: Optional[Path]) -> dict:
    """Lade Kundenkonfiguration aus YAML."""
    if config_path is None:
        return {}
    
    if not config_path.exists():
        print(f" Konfigurationsdatei nicht gefunden: {config_path}")
        return {}
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(f" Fehler beim Lesen der Konfiguration: {e}")
        return {}
    except Exception as e:
        print(f" Unerwarteter Fehler: {e}")
        return {}

def generate_report_pipeline(
    customer_name: str,
    ip: str,
    month: str,
    compare_month: Optional[str] = None,
    config_path: Optional[Path] = None,
    output_dir: Path = Path("./reports"),
    archive: bool = True,
    verbose: bool = False
) -> Dict[str, Any]:
    """
    Generiere einen vollständigen Shodan Report.
    
    Args:
        customer_name: Name des Kunden
        ip: IP-Adresse
        month: Zielmonat (YYYY-MM)
        compare_month: Vergleichsmonat (YYYY-MM, optional)
        config_path: Pfad zur Kundenkonfiguration
        output_dir: Verzeichnis für temporäre PDFs
        archive: Ob der Report archiviert werden soll
        verbose: Ausführliche Ausgabe
    
    Returns:
        Dictionary mit Ergebnis und Metadaten
    """
    load_dotenv()
    
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {
            "success": False,
            "error": "SHODAN_API_KEY nicht gesetzt. Bitte .env Datei prüfen."
        }
    
    if verbose:
        print(f"Lade Shodan Daten für {ip}...")
    
    try:
        # 1. Shodan Daten abrufen
        client = ShodanClient(api_key)
        raw_data = client.get_host(ip)
        snapshot = parse_shodan_host(raw_data)
        
        # 2. Snapshot speichern
        save_snapshot(snapshot, customer_name, month)
        
        # 3. Vorherigen Snapshot laden (falls Vergleich)
        prev_snapshot = None
        if compare_month:
            prev_snapshot = load_snapshot(customer_name, compare_month)
            if verbose and prev_snapshot:
                print(f"Geladener Vergleichssnapshot für {compare_month}")
        
        # 4. Trend analysieren
        trend_text = analyze_trend(prev_snapshot, snapshot) if prev_snapshot else "Keine historischen Daten für Trendanalyse vorhanden."
        
        # 5. Bewertung und Risiko
        evaluation = evaluate_snapshot(snapshot)
        business_risk = prioritize_risk(evaluation)
        
        # 6. Management Text (HTML Tags entfernen)
        management_text = generate_management_text(business_risk, evaluation)
        management_text = re.sub(r'<[^>]+>', '', management_text)
        
        # 7. Technischer Anhang
        technical_json = build_technical_data(snapshot, prev_snapshot)
        
        # 8. PDF erstellen
        if verbose:
            print("Generiere PDF...")
        
        pdf_path = generate_pdf(
            customer_name=customer_name,
            month=month,
            ip=snapshot.ip,
            management_text=management_text,
            trend_text=trend_text,
            technical_json=technical_json,
            output_dir=output_dir
        )
        
        result = {
            "success": True,
            "pdf_path": pdf_path,
            "business_risk": business_risk.value,
            "customer": customer_name,
            "ip": ip,
            "month": month
        }
        
        # 9. Archivierung (optional)
        if archive:
            if verbose:
                print("Archiviere Report...")
            
            report_archiver = ReportArchiver()
            metadata = report_archiver.archive_report(
                pdf_path=pdf_path,
                customer_name=customer_name,
                month=month,
                ip=snapshot.ip
            )
            
            result["archived"] = True
            result["archive_path"] = metadata["pdf_path"]
            result["version"] = metadata["version"]
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "customer": customer_name,
            "ip": ip,
            "month": month
        }