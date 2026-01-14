from shodan_report.evaluation.models import EvaluationResult
from shodan_report.evaluation.risk_prioritization import BusinessRisk
from typing import Dict, Any, List, Optional


def _normalize_services_from_technical(technical_json: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    services: List[Dict[str, Any]] = []
    if not technical_json or not isinstance(technical_json, dict):
        return services

    services = technical_json.get("services") or []
    if not services and technical_json.get("open_ports"):
        services = []
        for p in technical_json.get("open_ports", []):
            if isinstance(p, dict):
                port = p.get("port")
                svc_product = p.get("service", {}).get("product") if isinstance(p.get("service"), dict) else p.get("product")
                svc_version = p.get("service", {}).get("version") if isinstance(p.get("service"), dict) else p.get("version")
                svc_banner = p.get("service", {}).get("banner") if isinstance(p.get("service"), dict) else p.get("banner")
                svc_cves = p.get("vulnerabilities", []) or p.get("service", {}).get("vulnerabilities", [])
            else:
                port = getattr(p, "port", None)
                svc_product = getattr(p, "product", None)
                svc_version = getattr(p, "version", None)
                svc_banner = getattr(p, "raw", None) or None
                svc_cves = getattr(p, "vulnerabilities", []) or []

            services.append({
                "port": port,
                "product": svc_product,
                "version": svc_version,
                "banner": svc_banner,
                "cves": svc_cves,
            })
    return services


def generate_management_text(
    business_risk: BusinessRisk,
    evaluation: EvaluationResult,
    technical_json: dict = None,
) -> str:
    """Generate a concise management-friendly summary.

    Behaviour:
    - If `evaluation.critical_points` exist, expand them (and include details when `technical_json` is provided).
    - If no critical points, return a short, management-focused summary (1-3 sentences) and
      reference the compact service table when `technical_json` contains services.
    """

    critical_points = getattr(evaluation, "critical_points", []) or []

    # Build expanded critical points text when available
    critical_points_text = ""
    if critical_points:
        services = _normalize_services_from_technical(technical_json)
        details_lines: List[str] = []
        if services:
            details_lines.append("\n\nIdentifizierte kritische Punkte (mit Details):")
            for pt in critical_points:
                details_lines.append(f"- {pt}")
                matched = []
                for s in services:
                    try:
                        port = s.get("port")
                        prod = s.get("product") or "unknown"
                        ver = s.get("version") or ""
                        banner = s.get("banner") or ""
                        cves = s.get("cves") or []
                    except Exception:
                        continue

                    pt_lower = (pt or "").lower()
                    prod_l = (prod or "").lower()
                    if (isinstance(port, int) and str(port) in pt_lower) or any(k in pt_lower for k in [prod_l, "ssh", "http", "https", "nginx", "apache"]):
                        matched.append((port, prod, ver, banner, cves))

                if matched:
                    for (port, prod, ver, banner, cves) in matched:
                        line = f"  - Port {port}: {prod} {ver}".strip()
                        if banner:
                            line += f" - Banner: {banner}"

                        if cves:
                            cve_ids = []
                            for cv in cves:
                                if isinstance(cv, dict):
                                    cid = cv.get("id") or cv.get("cve")
                                    if cid:
                                        cve_ids.append(str(cid))
                                        continue
                                cid = getattr(cv, "id", None) or getattr(cv, "cve", None)
                                if cid:
                                    cve_ids.append(str(cid))
                                else:
                                    cve_ids.append(str(cv))
                            line += f"; bekannte CVEs: {', '.join(cve_ids)}"

                        line += "; Empfehlung: Zugangskontrollen prüfen, Patches / Konfiguration anpassen"
                        details_lines.append(line)
                else:
                    details_lines.append("  - Keine direkten Service-Details im Snapshot gefunden; bitte technische Bewertung durchführen.")

            critical_points_text = "\n" + "\n".join(details_lines)
        else:
            # No services -> keep simple list
            critical_points_text = "\n\nIdentifizierte kritische Punkte:\n" + "\n".join(f"- {pt}" for pt in critical_points)

    # If no critical points, prepare compact per-service hints text fragment
    service_hints_text = ""
    if not critical_points:
        services = _normalize_services_from_technical(technical_json)
        if services:
            hints = ["\nKonkrete Hinweise zu erkannten Diensten:"]
            for s in services:
                port = s.get("port")
                prod = s.get("product") or "unknown"
                ver = s.get("version") or ""
                prod_l = (prod or "").lower()
                if port == 22 or "ssh" in prod_l:
                    short = "z.B. Fail2Ban, SSH-Keys"
                    hints.append(f"- Port {port}: SSH ({prod} {ver}) - Banner sichtbar; Kurz: {short}")
                elif port == 443 or "https" in prod_l:
                    short = "z.B. TLS>=1.2, sichere Cipher"
                    hints.append(f"- Port {port}: HTTPS ({prod}) - Zertifikat/Chain prüfen; Kurz: {short}")
                elif port in (80, 8080) or "http" in prod_l:
                    short = "z.B. HSTS, WAF"
                    hints.append(f"- Port {port}: HTTP ({prod}) - Default/Welcome-Seite möglich; Kurz: {short}")
                else:
                    short = "Zugriffsregeln prüfen"
                    hints.append(f"- Port {port}: {prod} - weitere Prüfung empfohlen; Kurz: {short}")

            service_hints_text = "\n" + "\n".join(hints)

    # Build concise management summaries per BusinessRisk
    if business_risk == BusinessRisk.MONITOR:
        base = (
            "Gesamteinschätzung:\n"
            "Die externe Sicherheitslage Ihrer IT-Systeme wird aktuell als stabil bewertet.\n\n"
            "Empfehlung:\n"
            "kein unmittelbarer Handlungsbedarf; regelmäßige Überwachung empfohlen.\n"
            "Nächste Schritte: Technik prüft innerhalb von 30 Tagen (Owner: IT)."
        )
        # If there are critical points, include their expanded details as well
        if critical_points:
            return base + critical_points_text
        if service_hints_text:
            base += "\n\nSiehe Kurzdetail-Tabelle im Bericht für betroffene Dienste."
        return base

    if business_risk == BusinessRisk.ATTENTION:
        base = (
            "Gesamteinschätzung:\n"
            "Die externe Sicherheitslage weist erhöhte Risiken auf.\n\n"
            "Empfehlung:\n"
            "Überprüfung durch Ihre IT-Abteilung empfohlen.\n"
            "Nächste Schritte: Technik prüft innerhalb von 14 Tagen (Owner: IT)."
        )
        # If there are critical points, include their expanded details as well
        if critical_points:
            return base + critical_points_text
        if service_hints_text:
            base += "\n\nSiehe Kurzdetail-Tabelle im Bericht für betroffene Dienste."
        return base

    # Default: CRITICAL
    base = (
        "Gesamteinschätzung:\n"
        "Die externe Sicherheitslage wird als kritisch eingestuft.\n\n"
        "Empfehlung:\n"
        "zeitnahes Handeln und sofortige technische Bewertung empfohlen.\n"
        "Nächste Schritte: Technik prüft innerhalb von 24 Stunden (Owner: IT)."
    )

    # If there are critical points, append their details
    if critical_points:
        return base + critical_points_text

    # If no critical points but there are service hints, append them
    if service_hints_text:
        return base + service_hints_text
    return base
