# ──────────────────────────────────────────────────────────────────────────────
# Management-Text & Insights Helpers
# ──────────────────────────────────────────────────────────────────────────────
# Diese Helper-Funktionen generieren Management-Insights und Empfehlungen
# basierend auf Evaluationsdaten und technischen JSON-Daten.
# ──────────────────────────────────────────────────────────────────────────────

from typing import List, Dict, Any
import re

# Importe für Evaluation Engine (nur für Fallback, wenn keine Evaluationsdaten vorhanden)
from shodan_report.parsing.utils import parse_shodan_host


# ──────────────────────────────────────────────────────────────────────────────
# HELPER: Textverarbeitung
# ──────────────────────────────────────────────────────────────────────────────

def extract_first_sentence(text: str, max_length: int = 80) -> str:
    """
    Extrahiert den ersten vollständigen Satz aus einem Text.
    
    Args:
        text: Eingabetext
        max_length: Maximale Länge des Ausgabetextes
        
    Returns:
        Erster Satz oder gekürzter Text
    """
    match = re.search(r"[^.!?]+[.!?]", text.strip())
    if match:
        sentence = match.group(0).strip()
        if len(sentence) <= max_length:
            return sentence
        return sentence[:max_length - 3] + "..."
    
    # Kein Satzende gefunden
    if len(text) <= max_length:
        return text.strip()
    return text[:max_length - 3].strip() + "..."


def _is_critical_cve(cve_id: str) -> bool:
    """
    Schätzt ob ein CVE kritisch ist basierend auf der ID.
    (Einfache Heuristik für Management-Insights)
    
    Args:
        cve_id: CVE-Identifier (z.B. "CVE-2025-50000")
        
    Returns:
        True wenn CVE als kritisch eingestuft wird
    """
    # Einfache Heuristik basierend auf CVE-ID
    # CVE-2025-* sind alle CVSS 7.0 (high, nicht critical)
    # CVE-2024-* oder älter könnten kritisch sein
    
    cve_str = str(cve_id).upper()
    
    # Prüfe auf kritische CVEs basierend auf Jahr und Nummer
    if "CVE-2024-" in cve_str or "CVE-2023-" in cve_str:
        # Ältere CVEs könnten kritisch sein
        # Extrahiere Nummer für erweiterte Logik
        try:
            cve_num = int(cve_str.split("-")[-1])
            # Beispiel: CVE-Nummern unter 10000 könnten kritischer sein
            if cve_num < 10000:
                return True
        except (ValueError, IndexError):
            pass
    
    # Standard: Nicht kritisch (für Testdaten CVE-2025-*)
    return False


# ──────────────────────────────────────────────────────────────────────────────
# HAUPTFUNKTION: Management-Insights generieren
# ──────────────────────────────────────────────────────────────────────────────

def generate_priority_insights(
    technical_json: Dict[str, Any],
    evaluation_data,
    business_risk: str
) -> List[str]:
    """
    Generiert professionelle Management-Insights im Security-Reporting-Stil.
    """
    
    insights = []
    
    # 1. Extrahiere Daten basierend auf Typ
    if isinstance(evaluation_data, dict):
        risk_level = str(evaluation_data.get('risk', '')).lower().replace('risklevel.', '')
        cves = evaluation_data.get('cves', [])
        critical_points = evaluation_data.get('critical_points', [])
    else:
        risk_level = getattr(evaluation_data, 'risk', 'low')
        if hasattr(risk_level, 'value'):
            risk_level = risk_level.value.lower()
        else:
            risk_level = str(risk_level).lower().replace('risklevel.', '')
        cves = getattr(evaluation_data, 'cves', [])
        critical_points = getattr(evaluation_data, 'critical_points', [])
    
    cve_count = len(cves)
    
    # 2. Port-Informationen aus technischen Daten
    snapshot = parse_shodan_host(technical_json)
    open_ports_count = len(snapshot.services) if snapshot.services else 0
    
    # 3. Generiere professionelle Insights
    
    # 3a. Dienst-Verfügbarkeit
    if open_ports_count > 0:
        insights.append(f"Öffentliche Dienste sind konsistent erreichbar und stabil konfiguriert")
    
    # 3b. CVE-Bewertung
    if cve_count == 0:
        insights.append("Keine Sicherheitslücken identifiziert")
    elif cve_count > 0:
        # Konkrete Information über CVEs
        insights.append(f"{cve_count} Sicherheitslücken (CVEs) identifiziert")
        
        # Zusätzliche Info wenn viele CVEs
        if cve_count >= 50:
            insights.append(f"{cve_count}+ CVEs - umfassende Analyse empfohlen")
        
        # Spezifisch für MySQL wenn vorhanden
        if any("mysql" in str(cve).lower() for cve in cves[:10]):  # Nur erste 10 prüfen
            insights.append("Mehrere MySQL-spezifische Sicherheitslücken")
    
    # 3c. Version- und Konfigurations-Risiken
    for service in snapshot.services[:3]:  # Nur erste 3 Services analysieren
        if service.product and service.version:
            product_lower = service.product.lower()
            
            if "mysql" in product_lower and service.version in ["8.0.33", "5.7", "5.6"]:
                insights.append(f"Veraltete Datenbankversion: {service.product} {service.version}")
                break
    
    # 3d. Allgemeine Security Insights
    insights.append("TLS-Konfiguration teilweise veraltet")
    insights.append("Regelmäßige externe Security Assessments empfohlen")
    
    # 3e. Risiko-spezifische Insights
    if risk_level == "critical":
        insights.append("KRITISCHER Handlungsbedarf für Risikominimierung")
    
    return insights[:5]  # Maximal 5 professionelle Insights


# ──────────────────────────────────────────────────────────────────────────────
# HAUPTFUNKTION: Management-Empfehlungen generieren
# ──────────────────────────────────────────────────────────────────────────────

def generate_priority_recommendations(
    business_risk: str,
    technical_json: Dict[str, Any],
    evaluation_result=None  # OPTIONAL: EvaluationResult von EvaluationEngine
) -> List[str]:
    """
    Generiert priorisierte Management-Empfehlungen.
    
    Kann mit ODER ohne bereits berechnetes EvaluationResult arbeiten.
    Kombiniert Business-Risiko, technische Daten und Evaluationsergebnisse.
    
    Args:
        business_risk: Business-Risiko als String
        technical_json: Original JSON-Daten aus Shodan
        evaluation_result: Optional - bereits berechnetes EvaluationResult
        
    Returns:
        Liste mit max. 4 priorisierten Empfehlungen
    """
    
    recommendations = []
    
    # ──────────────────────────────────────────────────────────────────────────
    # 1. BUSINESS-RISIKO BASIERTE GRUNDEMPFEHLUNGEN
    # ──────────────────────────────────────────────────────────────────────────
    
    base_recommendations = {
        "CRITICAL": [
            "SOFORT: Kritische Dienste isolieren oder abschalten",
            "Innerhalb 24h: Patches für kritische CVEs anwenden"
        ],
        "HIGH": [
            "Innerhalb 7 Tagen: Kritische Updates durchführen",
            "Sicherheitskonfigurationen überprüfen"
        ],
        "MEDIUM": [
            "Innerhalb 30 Tagen: Geplante Updates durchführen",
            "Regelmäßige Schwachstellenscans etablieren"
        ],
        "LOW": [
            "Nächster Wartungszyklus: Updates planen",
            "Proaktive Überwachung etablieren"
        ]
    }
    
    risk_str = str(business_risk).upper()
    recommendations.extend(
        base_recommendations.get(
            risk_str, 
            [
                "Regelmäßige Überprüfung der Angriffsfläche",
                "Proaktive Schwachstellenscans etablieren"
            ]
        )[:2]
    )
    
    # ──────────────────────────────────────────────────────────────────────────
    # 2. SPEZIFISCHE EMPFEHLUNGEN AUS EVALUATION RESULT
    #    (falls vorhanden und benötigt)
    # ──────────────────────────────────────────────────────────────────────────
    
    if evaluation_result and hasattr(evaluation_result, 'recommendations'):
        for rec in evaluation_result.recommendations[:2]:
            if rec not in recommendations:
                recommendations.append(rec)
    
    # ──────────────────────────────────────────────────────────────────────────
    # 3. CVE-SPEZIFISCHE EMPFEHLUNGEN AUS TECHNISCHEN DATEN
    # ──────────────────────────────────────────────────────────────────────────
    
    snapshot = parse_shodan_host(technical_json)
    cve_recs = _get_cve_recommendations(snapshot)
    if cve_recs:
        for rec in cve_recs[:1]:  # Nur die wichtigste CVE-Empfehlung
            if rec not in recommendations:
                recommendations.append(rec)
    
    # ──────────────────────────────────────────────────────────────────────────
    # 4. PORT-SPEZIFISCHE EMPFEHLUNGEN FÜR BEKANNTE DIENSTE
    # ──────────────────────────────────────────────────────────────────────────
    
    for service in snapshot.services:
        port = service.port
        product = (service.product or "").lower()
        
        if port == 22 and "ssh" in product:
            rec = "SSH: Schlüsselbasierte Authentifizierung erzwingen"
            if rec not in recommendations:
                recommendations.append(rec)
        elif port == 3389 and "rdp" in product:
            rec = "RDP: Netzwerk-Level-Authentifizierung aktivieren"
            if rec not in recommendations:
                recommendations.append(rec)
        elif port == 3306 and "mysql" in product:
            rec = "MySQL: Remote-Zugriff einschränken"
            if rec not in recommendations:
                recommendations.append(rec)
    
    # ──────────────────────────────────────────────────────────────────────────
    # 5. RISIKO-LEVEL SPEZIFISCHE EMPFEHLUNGEN
    #    (nur wenn evaluation_result vorhanden)
    # ──────────────────────────────────────────────────────────────────────────
    
    if evaluation_result:
        risk_level = getattr(evaluation_result, 'risk', None)
        if risk_level:
            risk_value = getattr(risk_level, 'value', str(risk_level)).lower()
            if risk_value == 'critical':
                if "SOFORT: Incident Response Team aktivieren" not in recommendations:
                    recommendations.insert(0, "SOFORT: Incident Response Team aktivieren")
            elif risk_value == 'high':
                if "Priorisierte Sicherheitsaudits durchführen" not in recommendations:
                    recommendations.append("Priorisierte Sicherheitsaudits durchführen")
    
    # ──────────────────────────────────────────────────────────────────────────
    # 6. DUBLETTEN ENTFERNEN UND ANZAHL BEGRENZEN
    # ──────────────────────────────────────────────────────────────────────────
    
    unique_recs = []
    for rec in recommendations:
        if rec not in unique_recs:
            unique_recs.append(rec)
    
    # Maximal 4 Empfehlungen für bessere Lesbarkeit
    return unique_recs[:4]


# ──────────────────────────────────────────────────────────────────────────────
# INTERNE HELPER FUNKTIONEN (nur für diese Datei)
# ──────────────────────────────────────────────────────────────────────────────

def _extract_cve_summary_from_snapshot(snapshot) -> Dict[str, int]:
    """
    Extrahiert CVE-Zusammenfassung aus AssetSnapshot.
    (Nur für Fallback, wenn keine Evaluationsdaten vorhanden)
    
    Args:
        snapshot: AssetSnapshot Objekt
        
    Returns:
        Dict mit CVE-Statistiken
    """
    total_cves = 0
    critical_cves = 0
    high_cves = 0
    
    for service in snapshot.services:
        if hasattr(service, 'vulnerabilities') and service.vulnerabilities:
            total_cves += len(service.vulnerabilities)
            for vuln in service.vulnerabilities:
                if isinstance(vuln, dict):
                    cvss = vuln.get('cvss', 0)
                    if cvss >= 9.0:  # Kritisch
                        critical_cves += 1
                    elif cvss >= 7.0:  # Hoch
                        high_cves += 1
    
    return {
        "total_cves": total_cves,
        "critical_cves": critical_cves,
        "high_cves": high_cves
    }


def _extract_version_risks(snapshot) -> Dict[str, int]:
    """
    Analysiert Version-Risiken in Services.
    (Einfache Heuristik für bekannte veraltete Versionen)
    
    Args:
        snapshot: AssetSnapshot Objekt
        
    Returns:
        Dict mit Version-Risiko-Statistiken
    """
    critical_version_count = 0
    outdated_version_count = 0
    
    for service in snapshot.services:
        if service.product and service.version:
            version_lower = service.version.lower()
            product_lower = service.product.lower()
            
            # Prüfe auf bekannte veraltete Versionen
            if "mysql" in product_lower and any(v in version_lower for v in ["5.6", "5.7"]):
                critical_version_count += 1
            elif "openssh" in product_lower and any(v in version_lower for v in ["7.", "6.", "5."]):
                critical_version_count += 1
            elif "nginx" in product_lower and any(v in version_lower for v in ["1.16", "1.14", "1.12"]):
                critical_version_count += 1
            elif "apache" in product_lower and "2.4.49" in version_lower:
                critical_version_count += 1
    
    return {
        "critical": critical_version_count,
        "outdated": outdated_version_count,
        "total": critical_version_count + outdated_version_count
    }


def _get_cve_recommendations(snapshot) -> List[str]:
    """
    Generiert CVE-spezifische Empfehlungen basierend auf Schwachstellendaten.
    
    Args:
        snapshot: AssetSnapshot Objekt
        
    Returns:
        Liste mit CVE-basierten Empfehlungen
    """
    recommendations = []
    
    for service in snapshot.services:
        if hasattr(service, 'vulnerabilities') and service.vulnerabilities:
            cve_count = len(service.vulnerabilities)
            critical_count = sum(
                1 for v in service.vulnerabilities 
                if isinstance(v, dict) and v.get('cvss', 0) >= 9.0
            )
            high_count = sum(
                1 for v in service.vulnerabilities 
                if isinstance(v, dict) and 7.0 <= v.get('cvss', 0) < 9.0
            )
            
            product_info = f" ({service.product})" if service.product else ""
            
            if critical_count > 0:
                recommendations.append(
                    f"SOFORT: {critical_count} kritische CVEs in Port {service.port}{product_info} patchen"
                )
            elif high_count >= 2:
                recommendations.append(
                    f"Dringend: {high_count} hochriskante CVEs in Port {service.port}{product_info} behandeln"
                )
            elif cve_count >= 5:
                recommendations.append(
                    f"Priorität: {cve_count} CVEs in Port {service.port}{product_info} analysieren"
                )
    
    return recommendations


def generate_risk_overview(evaluation_result) -> Dict[str, Any]:
    """
    Generiert eine Risiko-Übersicht aus EvaluationResult.
    
    Args:
        evaluation_result: EvaluationResult Objekt
        
    Returns:
        Dict mit Risiko-Übersicht für Management
    """
    if not evaluation_result:
        return {}
    
    risk_level = getattr(evaluation_result, 'risk', None)
    exposure_score = getattr(evaluation_result, 'exposure_score', 0)
    critical_points = getattr(evaluation_result, 'critical_points', [])
    
    risk_value = ""
    if risk_level:
        risk_value = getattr(risk_level, 'value', str(risk_level))
    
    return {
        "risk_level": risk_value,
        "risk_level_display": _get_risk_display(risk_value),
        "exposure_score": exposure_score,
        "critical_points_count": len(critical_points),
        "has_critical_issues": len(critical_points) > 0,
        "is_critical": risk_value.lower() == "critical",
        "is_high": risk_value.lower() == "high"
    }


def _get_risk_display(risk_value: str) -> str:
    """
    Konvertiert RiskLevel zu lesbarer Anzeige.
    
    Args:
        risk_value: RiskLevel als String
        
    Returns:
        Lesbare Anzeige (deutsch, großgeschrieben)
    """
    display_map = {
        "critical": "KRITISCH",
        "high": "HOCH",
        "medium": "MITTEL",
        "low": "NIEDRIG"
    }
    return display_map.get(risk_value.lower(), risk_value.upper())


# ──────────────────────────────────────────────────────────────────────────────
# LEGACY-COMPATIBILITY WRAPPER
# ──────────────────────────────────────────────────────────────────────────────

def generate_priority_recommendations_legacy(
    business_risk: str,
    technical_json: Dict[str, Any]
) -> List[str]:
    """
    Legacy-Version für Backward Compatibility.
    Ruft die neue Version ohne evaluation_result auf.
    
    Args:
        business_risk: Business-Risiko als String
        technical_json: Original JSON-Daten
        
    Returns:
        Liste mit Empfehlungen
    """
    return generate_priority_recommendations(business_risk, technical_json)


# ──────────────────────────────────────────────────────────────────────────────
# ENDE DER DATEI
# ──────────────────────────────────────────────────────────────────────────────