import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import re
import yaml

from dotenv import load_dotenv

from shodan_report.clients.shodan_client import ShodanClient
from shodan_report.parsing.utils import parse_shodan_host
from shodan_report.persistence.snapshot_manager import save_snapshot, load_snapshot
from shodan_report.evaluation.evaluation_engine import evaluate_snapshot
from shodan_report.evaluation.risk_prioritization import prioritize_risk
from shodan_report.reporting.management_text import generate_management_text
from shodan_report.reporting.trend import analyze_trend
from shodan_report.reporting.technical_data import build_technical_data
from shodan_report.pdf.pdf_generator import generate_pdf
from shodan_report.archiver.report_archiver import ReportArchiver
from shodan_report.evaluation import Evaluation, RiskLevel

def load_customer_config(config_path: Optional[Path]) -> dict:
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
    config = load_customer_config(config_path)
    report_config = config.get("report", {})
    include_trend = config.get("report", {}).get("include_trend_analysis", True)
    if not include_trend:
        trend_text = "Trendanalyse deaktiviert (Kundenkonfiguration)."

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
        evaluation_dict = evaluation_to_dict(evaluation)

        business_risk = prioritize_risk(evaluation)

        business_risk_str = business_risk.value.upper() if hasattr(business_risk, 'value') else str(business_risk).upper()
        
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
            evaluation=evaluation_dict,        
            business_risk=business_risk_str, 
            output_dir=output_dir,
            config=config
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
    
def evaluation_to_dict(evaluation_obj: Evaluation) -> Dict[str, Any]:
        """
        Konvertiere Evaluation-Objekt zu einem aussagekräftigen Dictionary.
        
        Die PDF-Sektionen brauchen:
        - exposure_level (1-5) für Management-Sektion
        - critical_points_count für Risikobewertung
        - risk_score (numerisch) für Visualisierungen
        """
        
        # 1. Exposure-Level aus critical_points berechnen
        exposure_level = _calculate_exposure_level(evaluation_obj.critical_points)
        
        # 2. Risk-Score aus RiskLevel Enum
        risk_score_mapping = {
            RiskLevel.LOW: 2,
            RiskLevel.MEDIUM: 5, 
            RiskLevel.HIGH: 8
        }
        risk_score = risk_score_mapping.get(evaluation_obj.risk, 3)
        
        # 3. Kritische Dienste identifizieren
        critical_services = []
        ssh_ports = []
        rdp_ports = []
        
        for point in evaluation_obj.critical_points:
            if "SSH" in point.upper() or "ssh" in point:
                ssh_ports.append(point)
                critical_services.append("SSH")
            elif "RDP" in point.upper() or "rdp" in point:
                rdp_ports.append(point)
                critical_services.append("RDP")
        
        return {
            "ip": evaluation_obj.ip,
            "risk": evaluation_obj.risk.value,  # "low", "medium", "high"
            "risk_score": risk_score,  # numerisch: 2, 5, 8
            "critical_points": evaluation_obj.critical_points,
            "critical_points_count": len(evaluation_obj.critical_points),
            "exposure_level": exposure_level,  # 1-5
            "critical_services": list(set(critical_services)),  # Einzigartige Dienste
            "has_ssh": len(ssh_ports) > 0,
            "has_rdp": len(rdp_ports) > 0,
            "ssh_ports": ssh_ports,
            "rdp_ports": rdp_ports
        }


def _calculate_exposure_level(critical_points: List[str]) -> int:
    """
    Berechne Exposure-Level (1-5) basierend auf kritischen Punkten.
    
    Logik:
    - 0 Punkte: Level 1 (sehr niedrig)
    - 1-2 Punkte: Level 2 (niedrig) 
    - 3-4 Punkte: Level 3 (mittel)
    - 5-6 Punkte: Level 4 (hoch)
    - 7+ Punkte: Level 5 (sehr hoch)
    """
    count = len(critical_points)
    
    if count == 0:
        return 1
    elif count <= 2:
        return 2
    elif count <= 4:
        return 3
    elif count <= 6:
        return 4
    else:
        return 5