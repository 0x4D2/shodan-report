import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import re
import yaml

from dotenv import load_dotenv

from shodan_report.clients.shodan_client import ShodanClient
from shodan_report.parsing.utils import parse_shodan_host
from shodan_report.persistence.snapshot_manager import save_snapshot, load_snapshot
from shodan_report.evaluation import (
    EvaluationEngine,
    RiskLevel,
)  # ⬅️ GEÄNDERT: EvaluationEngine
from shodan_report.evaluation.risk_prioritization import prioritize_risk
from shodan_report.reporting.management_text import generate_management_text
from shodan_report.reporting.trend import analyze_trend
from shodan_report.reporting.technical_data import build_technical_data
from shodan_report.pdf.pdf_generator import generate_pdf
from shodan_report.archiver.report_archiver import ReportArchiver


def load_customer_config(config_path: Optional[Path]) -> dict:
    if config_path is None:
        return {}

    if not config_path.exists():
        print(f" Konfigurationsdatei nicht gefunden: {config_path}")
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
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
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Generiere einen vollständigen Shodan Report mit NEUER Evaluation Engine.

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
            "error": "SHODAN_API_KEY nicht gesetzt. Bitte .env Datei prüfen.",
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
        else:
            # Auto-compare: use previous month if available
            prev_month_match = re.match(r"^(\d{4})-(\d{2})$", str(month))
            if prev_month_match:
                year = int(prev_month_match.group(1))
                mon = int(prev_month_match.group(2))
                if mon == 1:
                    year -= 1
                    mon = 12
                else:
                    mon -= 1
                auto_compare_month = f"{year:04d}-{mon:02d}"
                prev_snapshot = load_snapshot(customer_name, auto_compare_month)
                if prev_snapshot:
                    compare_month = auto_compare_month
                    if verbose:
                        print(f"Auto-Vergleich mit {compare_month}")

        # 4. Trend analysieren
        if not include_trend:
            trend_text = "Trendanalyse deaktiviert (Kundenkonfiguration)."
        else:
            trend_text = analyze_trend(prev_snapshot, snapshot) if prev_snapshot else ""

        engine = EvaluationEngine()
        evaluation_result = engine.evaluate(snapshot)  # ← EvaluationResult Objekt

        # 6. Business Risk berechnen
        business_risk = prioritize_risk(evaluation_result)
        business_risk_str = str(business_risk).upper()

        # 8. Technischer Anhang (frühzeitig bauen, damit Management-Text
        # detaillierte Dienst-Flags erzeugen kann)
        technical_json = build_technical_data(snapshot, prev_snapshot)

        # 7. Management Text (HTML Tags entfernen)
        management_text = generate_management_text(
            business_risk, evaluation_result, technical_json
        )  # ← evaluation_result + technical_json
        management_text = re.sub(r"<[^>]+>", "", management_text)
        if verbose:
            print("\n--- Management Text (generated) ---\n")
            print(management_text)
            print("\n--- End Management Text ---\n")

        # 9. PDF erstellen
        if verbose:
            print("Generiere PDF...")

        # Konvertiere EvaluationResult zu Dict für PDF
        evaluation_dict = evaluation_result_to_dict(evaluation_result)

        # Füge in runner.py nach evaluation_result_to_dict() hinzu:
        print(f"\nEvaluation Dict nach Konvertierung:")
        print(f"  risk: {evaluation_dict.get('risk')}")
        print(f"  exposure_score: {evaluation_dict.get('exposure_score')}")
        print(f"  exposure_level: {evaluation_dict.get('exposure_level')}")
        print(f"  exposure: {evaluation_dict.get('exposure')}")
        print("=" * 50 + "\n")

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
            config=config,
            compare_month=compare_month,
        )

        result = {
            "success": True,
            "pdf_path": pdf_path,
            "business_risk": str(business_risk.value),
            "customer": customer_name,
            "ip": ip,
            "month": month,
        }

        # 10. Archivierung (optional)
        if archive:
            if verbose:
                print("Archiviere Report...")

            report_archiver = ReportArchiver()
            metadata = report_archiver.archive_report(
                pdf_path=pdf_path,
                customer_name=customer_name,
                month=month,
                ip=snapshot.ip,
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
            "month": month,
        }


def evaluation_result_to_dict(evaluation_result) -> Dict[str, Any]:
    """
    Konvertiere EvaluationResult-Objekt zu einem Dictionary für PDF-Generierung.

    WICHTIG: Neue Engine verwendet Enum RiskLevel (CRITICAL, HIGH, etc.)
    """
    # 1. Extrahiere Risk Level
    risk = evaluation_result.risk  # Ist ein RiskLevel Enum

    if hasattr(risk, "value"):
        risk_str = risk.value.lower()  # "critical", "high", etc.
    else:
        risk_str = str(risk).lower()
        # Falls es noch "risklevel." Präfix hat
        if risk_str.startswith("risklevel."):
            risk_str = risk_str[10:]

    # Konvertiere Enum zu String und dann lowercase für Kompatibilität
    risk_str = str(risk).lower()

    # 2. Mapping für risk_score (für Visualisierung)
    risk_score_mapping = {"critical": 10, "high": 8, "medium": 5, "low": 2}
    risk_score = risk_score_mapping.get(risk_str, 3)

    # 3. Kritische Dienste identifizieren
    critical_services = []
    ssh_ports = []
    rdp_ports = []
    mysql_ports = []

    for point in evaluation_result.critical_points:
        point_lower = point.lower()

        if "ssh" in point_lower:
            ssh_ports.append(point)
            critical_services.append("SSH")
        elif "rdp" in point_lower:
            rdp_ports.append(point)
            critical_services.append("RDP")
        elif "mysql" in point_lower or "database" in point_lower:
            mysql_ports.append(point)
            critical_services.append("MySQL")

    # 4. Exposure Level: Konvertiere 1-5 Score zu "X/5" für PDF
    exposure_score = evaluation_result.exposure_score
    exposure_level_str = f"{exposure_score}/5"

    return {
        "ip": evaluation_result.ip if hasattr(evaluation_result, "ip") else "N/A",
        "risk": risk_str,  # "critical", "high", etc.
        "risk_score": risk_score,  # numerisch: 2, 5, 8, 10
        "critical_points": evaluation_result.critical_points,
        "critical_points_count": len(evaluation_result.critical_points),
        "exposure_score": exposure_score,  # Original 1-5 Score
        "exposure_level": exposure_level_str,  # String "5/5" für Template
        "exposure": exposure_level_str,  # Alternative für Template-Kompatibilität
        "critical_services": list(set(critical_services)),
        "has_ssh": len(ssh_ports) > 0,
        "has_rdp": len(rdp_ports) > 0,
        "has_mysql": len(mysql_ports) > 0,
        "ssh_ports": ssh_ports,
        "rdp_ports": rdp_ports,
        "mysql_ports": mysql_ports,
    }


def _calculate_exposure_level(critical_points: List[str]) -> int:
    """Veraltet - wird jetzt von EvaluationEngine berechnet."""
    print(
        "⚠️  _calculate_exposure_level ist deprecated - nutze evaluation_result.exposure_score"
    )
    return 3  # Fallback
