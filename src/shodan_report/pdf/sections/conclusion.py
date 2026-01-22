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
    elements.append(Paragraph("<b>7. Fazit</b>", styles.get("heading1") or styles.get("heading2") or styles["normal"]))
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

    if effective_level == "CRITICAL":
        state = "kritisch"
        rec = "sofort priorisierte Maßnahmen"
    elif effective_level == "HIGH":
        state = "erhöht"
        rec = "zeitnahe Maßnahmen"
    elif effective_level == "MEDIUM":
        state = "moderat"
        rec = "geplante Maßnahmen"
    else:
        state = "kontrolliert"
        rec = "kontinuierliche Überwachung"

    conclusion_text = (
        f"Die externe Angriffsfläche ist {state}; empfohlen wird {rec}."
    )

    elements.append(Paragraph(conclusion_text, styles["normal"]))
    elements.append(Spacer(1, 8))

    # Erweiterte, management-orientierte Handlungsempfehlungen (kurz)
    elements.append(Paragraph("Empfohlene nächste Schritte:", styles.get("heading2") or styles["normal"]))
    elements.append(Spacer(1, 6))
    try:
        elements.append(Paragraph("• Kurzfristig (innerhalb 30 Tagen): Priorisieren und patchen kritischer CVEs; nicht benötigte Management-/Datenbankdienste abschalten oder per Firewall einschränken; Backups prüfen.", styles["bullet"]))
        elements.append(Paragraph("• Mittelfristig (30–90 Tage): Zugriffshärtung (MFA, SSH Key-Only, VPN/Jumphost), Netzwerksegmentierung und Rollenbasierte Zugriffskontrollen implementieren.", styles["bullet"]))
        elements.append(Paragraph("• Laufend: regelmäßige automatisierte Scans, Trendreports, Alerting sowie Benennung eines Owners für Remediation und Reporting.", styles["bullet"]))
    except Exception:
        # Fallback: single-line recommendation if bullet style missing
        elements.append(Paragraph("Empfohlene Schritte: kurzfristige Patches und Zugriffsbeschränkungen; mittelfristig Zugriffshärtung; laufendes Monitoring.", styles["normal"]))

    elements.append(Spacer(1, 8))

    # Verweis auf detaillierte Maßnahmen
    elements.append(Paragraph("Details und priorisierte Maßnahmen finden sich im Abschnitt 'Priorisierte Handlungsempfehlungen'.", styles["normal"]))


def _extract_risk_level(business_risk) -> str:
    """Extrahiert Risiko-Level (gleiche Funktion wie in recommendations)."""
    if isinstance(business_risk, dict):
        return str(business_risk.get("level", "MEDIUM"))
    elif isinstance(business_risk, str):
        return business_risk
    else:
        return str(business_risk)
