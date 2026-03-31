"""
Fazit-Section für PDF-Reports.
"""

from typing import List, Dict
import os
from reportlab.platypus import Spacer, Paragraph


def create_conclusion_section(
    elements: List, styles: Dict, customer_name: str, business_risk: str, context: object = None
) -> None:
    """
    Erstelle Fazit-Section mit abschließender Bewertung.

    Args:
        elements: Liste der PDF-Elemente
        styles: Dictionary mit PDF-Styles
        customer_name: Name des Kunden
        business_risk: Business Risk Level (HIGH/MEDIUM/LOW)
    """
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("<b>6. Fazit</b>", styles.get("heading1") or styles.get("heading2") or styles["normal"]))
    elements.append(Spacer(1, 12))

    # Determine risk_level: prefer context-derived evaluation/mdata to stay consistent
    risk_level = _extract_risk_level(business_risk)
    if context is not None:
        try:
            # avoid importing heavy modules at top-level; local import
            from .data.management_data import prepare_management_data

            technical_json = getattr(context, "technical_json", {}) or {}
            evaluation = getattr(context, "evaluation", {}) or {}
            mdata = prepare_management_data(technical_json, evaluation)
            if mdata.get("risk_level"):
                risk_level = mdata.get("risk_level")
        except Exception:
            pass

    # Optional: adjust risk level based on critical CVEs (OSINT/NVD)
    critical_cves_count = 0
    if context is not None:
        try:
            from .data.cve_enricher import enrich_cves

            technical_json = getattr(context, "technical_json", {}) or {}
            evaluation = getattr(context, "evaluation", {}) or {}

            # Use unique CVEs from management data if available
            try:
                from .data.management_data import prepare_management_data

                mdata = prepare_management_data(technical_json, evaluation)
                cve_ids = mdata.get("unique_cves", []) or []
            except Exception:
                cve_ids = evaluation.get("cves", []) if isinstance(evaluation, dict) else []

            lookup_nvd = os.environ.get("NVD_LIVE") == "1"
            if lookup_nvd and cve_ids:
                enriched = enrich_cves(cve_ids, technical_json, lookup_nvd=True)
                for ent in enriched:
                    try:
                        cvss = ent.get("cvss")
                        if cvss is not None and float(cvss) >= 9.0:
                            critical_cves_count += 1
                    except Exception:
                        continue
        except Exception:
            critical_cves_count = 0

    effective_level = risk_level.upper()
    if critical_cves_count >= 3 and effective_level in ["LOW", "MEDIUM"]:
        effective_level = "HIGH"
    elif critical_cves_count >= 1 and effective_level == "LOW":
        effective_level = "MEDIUM"

    # Apply TLS/EOL awareness — align Fazit with management section boosts
    # so the conclusion never contradicts the technical findings displayed above.
    if effective_level in ("LOW", "MONITOR") and context is not None:
        try:
            _tj = getattr(context, "technical_json", {}) or {}
            _insecure_v = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
            _has_tls = False
            for _s in (_tj.get("services") or _tj.get("open_ports") or []):
                if isinstance(_s, dict):
                    _ssl = (_s.get("ssl_info") or {})
                    for _v in ((_ssl.get("versions") or []) if isinstance(_ssl, dict) else []):
                        if not str(_v).startswith("-") and str(_v).strip() in _insecure_v:
                            _has_tls = True
                            break
                if _has_tls:
                    break
            _has_eol_tag = "eol-product" in [str(t).lower() for t in (_tj.get("tags") or [])]
            _has_eol_svc = False
            try:
                from .data.management_data import prepare_management_data as _pm
                from shodan_report.evaluation.eol import scan_services_for_eol as _se
                _svcs = [{"port": s.get("port"), "product": s.get("product") or "", "version": s.get("version") or ""}
                         for s in (_tj.get("services") or _tj.get("open_ports") or []) if isinstance(s, dict)]
                _has_eol_svc = any(f.get("eol_status") in ("eol", "near_eol") for f in _se(_svcs))
            except Exception:
                pass
            if _has_tls or _has_eol_tag or _has_eol_svc:
                effective_level = "MEDIUM"
        except Exception:
            pass

    # Collect contribution factors for conclusion text (mirrors management.py boost logic)
    _contrib = []
    if context is not None:
        try:
            _tj = getattr(context, "technical_json", {}) or {}
            _insecure_v = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
            for _s in (_tj.get("services") or _tj.get("open_ports") or []):
                if isinstance(_s, dict):
                    for _v in ((_s.get("ssl_info") or {}).get("versions") or []):
                        if not str(_v).startswith("-") and str(_v).strip() in _insecure_v:
                            _contrib.append("unsichere TLS-Protokolle")
                            break
            _has_eol_c = "eol-product" in [str(t).lower() for t in (_tj.get("tags") or [])]
            if not _has_eol_c:
                try:
                    from shodan_report.evaluation.eol import scan_services_for_eol as _sec
                    _svcs_c = [{"port": s.get("port"), "product": s.get("product") or "",
                                "version": s.get("version") or ""}
                               for s in (_tj.get("services") or _tj.get("open_ports") or []) if isinstance(s, dict)]
                    _has_eol_c = any(f.get("eol_status") in ("eol", "near_eol") for f in _sec(_svcs_c))
                except Exception:
                    pass
            if _has_eol_c:
                _contrib.append("EOL-Software")
            if critical_cves_count > 0:
                _contrib.append(f"{critical_cves_count} kritische CVEs (Inferred)")
        except Exception:
            pass

    _contrib_str = ", ".join(_contrib) + " — " if _contrib else ""

    if effective_level == "CRITICAL":
        conclusion_text = (
            f"Die externe Angriffsfläche ist <b>kritisch</b>. "
            f"{_contrib_str}Sofortiger Handlungsbedarf."
        )
    elif effective_level == "HIGH":
        conclusion_text = (
            f"Die externe Angriffsfläche ist <b>hoch</b>. "
            f"{_contrib_str}Zeitnahe Absicherung erforderlich."
        )
    elif effective_level == "MEDIUM":
        conclusion_text = (
            f"Die externe Angriffsfläche ist <b>erhöht</b>. "
            f"{_contrib_str}Konkrete Handlungsfelder vorhanden — geplante Maßnahmen empfohlen."
        )
    else:
        conclusion_text = (
            "Die externe Angriffsfläche ist <b>kontrolliert</b>. "
            "Kein akuter Handlungsbedarf; kontinuierliche Überwachung empfohlen."
        )

    elements.append(Paragraph(conclusion_text, styles["normal"]))
    elements.append(Spacer(1, 8))

    # Empfohlene nächste Schritte — calibrated per risk level
    elements.append(Paragraph("Empfohlene nächste Schritte:", styles.get("heading2") or styles["normal"]))
    elements.append(Spacer(1, 6))
    try:
        if effective_level in ("CRITICAL", "HIGH"):
            elements.append(Paragraph("• Kurzfristig (0–48 h): Kritische Dienste (RDP, Datenbanken) per VPN/Firewall abschirmen; EOL-Systeme inventarisieren und Notfall-Patches prüfen.", styles["bullet"]))
            elements.append(Paragraph("• Kurzfristig (7 Tage): Priorisierte CVEs patchen; TLS 1.0/1.1 deaktivieren; MFA auf allen Admin-Zugängen aktivieren.", styles["bullet"]))
            elements.append(Paragraph("• Laufend: Monatliche Exposure-Messung, Alerting bei neuen offenen Ports, Owner für Remediation benennen.", styles["bullet"]))
        elif effective_level == "MEDIUM":
            elements.append(Paragraph("• Kurzfristig (30 Tage): Nicht benötigte Dienste abschalten; TLS-Konfiguration härten (TLS 1.2+); CVE-Monitoring einrichten.", styles["bullet"]))
            elements.append(Paragraph("• Mittelfristig (60–90 Tage): Zugriffshärtung (MFA, Key-Only SSH, VPN/Jumphost); EOL-Ablaufplan erstellen.", styles["bullet"]))
            elements.append(Paragraph("• Laufend: Monatliche Wiederholung, Trendbeobachtung, Owner benennen.", styles["bullet"]))
        else:
            elements.append(Paragraph("• Monatliche Wiederholung der Analyse zur Trendbeobachtung.", styles["bullet"]))
            elements.append(Paragraph("• TLS-Konfiguration und Security-Header regelmäßig prüfen.", styles["bullet"]))
    except Exception:
        elements.append(Paragraph("Empfohlene Schritte: kurzfristige Patches und Zugriffsbeschränkungen; mittelfristig Zugriffshärtung; laufendes Monitoring.", styles["normal"]))


def _extract_risk_level(business_risk) -> str:
    """Extrahiert Risiko-Level (gleiche Funktion wie in recommendations)."""
    if isinstance(business_risk, dict):
        return str(business_risk.get("level", "MEDIUM"))
    elif isinstance(business_risk, str):
        return business_risk
    else:
        return str(business_risk)
