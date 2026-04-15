import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import re
import yaml

from dotenv import load_dotenv

from shodan_report.clients.shodan_client import ShodanClient
from shodan_report.parsing.utils import parse_shodan_host
from shodan_report.persistence.snapshot_manager import save_snapshot, load_snapshot
from shodan_report.pdf.sections.trend import _month_abbr as _abbr
from shodan_report.evaluation import (
    EvaluationEngine,
    RiskLevel,
)  # ⬅️ GEÄNDERT: EvaluationEngine
from shodan_report.evaluation.risk_prioritization import prioritize_risk
from shodan_report.reporting.management_text import generate_management_text
from shodan_report.reporting.report_validator import validate_report as _validate_report
from shodan_report.reporting.trend import analyze_trend
from shodan_report.reporting.technical_data import build_technical_data
from shodan_report.pdf.pdf_generator import generate_pdf
from shodan_report.pdf.sections.data.management_data import prepare_management_data
from shodan_report.pdf.sections.data.cve_enricher import enrich_cves
from shodan_report.archiver.report_archiver import ReportArchiver
from shodan_report.paths import reports_dir


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


def _prev_month(month_str: str) -> str:
    """Returns the YYYY-MM string for the month immediately before month_str."""
    year = int(month_str[:4])
    mon = int(month_str[5:7]) - 1
    if mon < 1:
        mon = 12
        year -= 1
    return f"{year:04d}-{mon:02d}"


def generate_report_pipeline(
    customer_name: str,
    ip: Optional[str],
    month: str,
    compare_month: Optional[str] = None,
    config_path: Optional[Path] = None,
    output_dir: Path = None,
    archive: bool = True,
    verbose: bool = False,
    domain: Optional[str] = None,
    note: Optional[str] = None,
    from_snapshot: bool = False,
) -> Dict[str, Any]:
    """
    Generiere einen vollständigen Shodan Report mit NEUER Evaluation Engine.

    Args:
        customer_name: Name des Kunden
        ip: IP-Adresse. Optional wenn domain angegeben — wird dann automatisch ermittelt.
        month: Zielmonat (YYYY-MM)
        compare_month: Vergleichsmonat (YYYY-MM, optional)
        config_path: Pfad zur Kundenkonfiguration
        output_dir: Verzeichnis für temporäre PDFs
        archive: Ob der Report archiviert werden soll
        verbose: Ausführliche Ausgabe
        domain: Kundendomain für Attack-Surface-Discovery (passives OSINT)
        from_snapshot: Kein Shodan-Aufruf — Snapshot aus Disk laden und PDF neu rendern

    Returns:
        Dictionary mit Ergebnis und Metadaten
    """
    config = load_customer_config(config_path)
    report_config = config.get("report", {})

    # --note CLI-Argument überschreibt cover_note aus YAML
    if note:
        config.setdefault("report", {})["cover_note"] = note

    # ── Customer-YAML: IP/Domain/Package aus Konfiguration lesen ─────────────
    customer_cfg = config.get("customer", {})

    # IP: explizites Argument hat Vorrang, dann YAML (einzeln oder Liste)
    if not ip:
        ip = customer_cfg.get("ip") or None
    if not ip:
        ips_list = customer_cfg.get("ips")
        if ips_list and isinstance(ips_list, list):
            ip = ips_list[0]

    # Domain: explizites Argument hat Vorrang, dann YAML
    if not domain:
        domain = customer_cfg.get("domain") or None

    # Package-basierte Sektion-Kontrolle in config einschreiben
    package = customer_cfg.get("package", "professional").lower()
    config["_package"] = package

    # enterprise → NVD Live automatisch
    if package == "enterprise":
        config.setdefault("nvd", {})["enabled"] = True

    include_trend = config.get("report", {}).get("include_trend_analysis", True)
    if not include_trend:
        trend_text = "Trendanalyse deaktiviert (Kundenkonfiguration)."

    load_dotenv()

    if output_dir is None:
        output_dir = reports_dir()

    # ── Attack Surface Discovery (passives OSINT) ──────────────────────────────────
    # Bei --from-snapshot keinen Scout starten — IP + Domain kommen aus dem Snapshot
    attack_surface = None
    if domain and not from_snapshot:
        try:
            from shodan_report.clients.domain_scout import scout_domain
            if verbose:
                print(f"[Scout] Starte Domain-Discovery für: {domain}")
            attack_surface = scout_domain(domain, verbose=verbose)
            # IP aus Scout übernehmen wenn nicht explizit gegeben
            if not ip:
                ip = attack_surface.primary_ip
                if not ip:
                    return {
                        "success": False,
                        "error": f"Domain Scout konnte keine verwertbare IP für '{domain}' ermitteln. "
                                 "Bitte --ip manuell angeben.",
                    }
                if verbose:
                    print(f"[Scout] Primäre IP ausgewählt: {ip}")
            # über den Config-Dict an PDF durchreichen (private key)
            config["_attack_surface"] = attack_surface
        except Exception as e:
            if verbose:
                print(f"[Scout] Warnung: Domain-Discovery fehlgeschlagen: {e}")
            # Non-fatal — Report läuft ohne Attack-Surface-Sektion weiter

    if not ip and not from_snapshot:
        return {
            "success": False,
            "error": "IP-Adresse fehlt und Domain-Discovery lieferte kein Ergebnis.",
        }

    if not from_snapshot:
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            return {
                "success": False,
                "error": "SHODAN_API_KEY nicht gesetzt. Bitte .env Datei prüfen.",
            }

    try:
        # ── Vormonats-Notiz anzeigen (falls vorhanden) ────────────────────────
        try:
            prev_note_month = _prev_month(month)
            prev_note_snap  = load_snapshot(customer_name, prev_note_month) if not ip else None
            prev_ip_guess   = ip or (prev_note_snap.ip if prev_note_snap else None)
            if prev_ip_guess:
                prev_note = ReportArchiver().load_cover_note(customer_name, prev_note_month, prev_ip_guess)
                if prev_note:
                    w = 60
                    m_label = _abbr(prev_note_month)
                    y_label = prev_note_month[:4]
                    print(f"\n  +{'─' * w}+")
                    print(f"  | Ihr Kommentar vom {m_label} {y_label:<{w - 22}}|")
                    print(f"  +{'─' * w}+")
                    words = prev_note.split()
                    line = ""
                    for word in words:
                        if len(line) + len(word) + 1 > w - 4:
                            print(f"  | {line:<{w - 4}} |")
                            line = word
                        else:
                            line = f"{line} {word}".strip()
                    if line:
                        print(f"  | {line:<{w - 4}} |")
                    print(f"  +{'─' * w}+\n")
        except Exception:
            pass

        if from_snapshot:
            # ── Snapshot-Modus: kein Shodan-Aufruf ───────────────────────────
            snapshot = load_snapshot(customer_name, month)
            if not snapshot:
                return {
                    "success": False,
                    "error": (
                        f"Kein gespeicherter Snapshot für '{customer_name}' / {month} gefunden. "
                        "Bitte erst einen Report ohne --from-snapshot generieren."
                    ),
                }
            if not ip:
                ip = snapshot.ip
            if verbose:
                print(f"[Snapshot] Lade gespeicherte Daten für {ip} ({month}) — kein Shodan-Aufruf.")
        else:
            # ── Normalmodus: Shodan-Aufruf ────────────────────────────────────
            if verbose:
                print(f"Lade Shodan Daten für {ip}...")
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
            if re.match(r"^\d{4}-\d{2}$", str(month)):
                auto_compare_month = _prev_month(month)
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
        # Ensure RDP findings always promote risk when externally exposed.
        try:
            rdp_detected = any(
                (getattr(s, "port", None) == 3389)
                or ("rdp" in (getattr(s, "product", "") or "").lower())
                or ("remote desktop" in (getattr(s, "product", "") or "").lower())
                for s in snapshot.services
            )
            if rdp_detected and not any("rdp" in str(p).lower() for p in evaluation_result.critical_points):
                # add explicit critical point and escalate risk to CRITICAL
                evaluation_result.critical_points.append("RDP öffentlich erreichbar (Runner-Override)")
                try:
                    evaluation_result.risk = RiskLevel.CRITICAL
                except Exception:
                    pass
        except Exception:
            pass

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

        # ── Report Logic Validation ───────────────────────────────────────────
        # Checks score ↔ text ↔ findings consistency. Non-fatal: prints warnings.
        try:
            _boosted_score = technical_json.get("exposure_score") or evaluation_result.exposure_score
            _violations = _validate_report(_boosted_score, management_text, technical_json)
            if _violations:
                print(f"\n[REPORT VALIDATOR] {len(_violations)} Konsistenzproblem(e) erkannt:")
                for _v in _violations:
                    print(f"  {_v}")
        except Exception:
            pass
        # ─────────────────────────────────────────────────────────────────────

        if verbose:
            print("\n--- Management Text (generated) ---\n")
            print(management_text)
            print("\n--- End Management Text ---\n")

        # 9. PDF erstellen
        if verbose:
            print("Generiere PDF...")

        # Konvertiere EvaluationResult zu Dict für PDF
        evaluation_dict = evaluation_result_to_dict(evaluation_result)

        # Expose previous exposure score for trend chart (if available)
        try:
            if prev_snapshot:
                prev_eval = engine.evaluate(prev_snapshot)
                prev_eval_dict = evaluation_result_to_dict(prev_eval)
                technical_json["previous_exposure_score"] = prev_eval_dict.get("exposure_score")
        except Exception:
            pass

        # ── Historische Exposure-Scores für 6-Monats-Chart (nur echte Daten) ──
        if include_trend:
            try:
                history_entries = []
                hist_month = month
                for _ in range(5):
                    hist_month = _prev_month(hist_month)
                    hist_snap = load_snapshot(customer_name, hist_month)
                    if hist_snap:
                        try:
                            hist_eval = engine.evaluate(hist_snap)
                            history_entries.insert(0, {
                                "month": hist_month,
                                "score": hist_eval.exposure_score,
                                "real": True,
                            })
                        except Exception:
                            pass

                history_entries.append({
                    "month": month,
                    "score": evaluation_result.exposure_score,
                    "real": True,
                })

                if len(history_entries) >= 2:
                    technical_json["exposure_history"] = history_entries
            except Exception:
                pass


        # Enriched CVEs for trend/high-risk counts (current + previous)
        try:
            lookup_nvd = bool((config.get("nvd") or {}).get("enabled", False))
            if os.environ.get("NVD_LIVE") == "1":
                lookup_nvd = True

            mdata_current = prepare_management_data(technical_json, evaluation_dict)
            enriched_current = enrich_cves(
                mdata_current.get("unique_cves", []),
                technical_json,
                lookup_nvd=lookup_nvd,
            )
            technical_json["cve_enriched"] = enriched_current

            if prev_snapshot and technical_json.get("previous_metrics") is not None:
                prev_eval = engine.evaluate(prev_snapshot)
                prev_eval_dict = evaluation_result_to_dict(prev_eval)
                prev_technical = build_technical_data(prev_snapshot, None)
                mdata_prev = prepare_management_data(prev_technical, prev_eval_dict)
                enriched_prev = enrich_cves(
                    mdata_prev.get("unique_cves", []),
                    prev_technical,
                    lookup_nvd=lookup_nvd,
                )
                prev_high = sum(1 for e in enriched_prev if (e.get("cvss") or 0) >= 9.0)
                technical_json["previous_metrics"]["Hochrisiko-CVEs"] = prev_high
        except Exception:
            # non-fatal: leave enriched data empty
            pass

        if verbose:
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

            # Notiz in Archiv-Metadaten speichern (aus --note oder YAML)
            note_to_save = (config.get("report") or {}).get("cover_note")
            if note_to_save:
                try:
                    report_archiver.save_cover_note(
                        customer_name=customer_name,
                        month=month,
                        ip=snapshot.ip,
                        note=note_to_save,
                    )
                    result["cover_note_saved"] = True
                except Exception:
                    pass

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