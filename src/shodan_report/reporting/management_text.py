# reporting/management_text.py
# ─────────────────────────────────────────────────────────────────────────────
# Management-Text-Generierung für Exposure-Reports
#
# Prinzip: Jedes Risikoszenario hat einen eigenen, spezifischen Text.
# Kein generisches "Risiko erkannt" — sondern konkreter Kontext,
# Begründung und Konsequenz für die Geschäftsführung.
# ─────────────────────────────────────────────────────────────────────────────

from shodan_report.evaluation.models import EvaluationResult
from shodan_report.evaluation.risk_prioritization import BusinessRisk
from typing import Dict, Any, List, Optional
import re

try:
    from shodan_report.evaluation.eol import scan_services_for_eol as _scan_eol
except Exception:
    _scan_eol = None


# ─────────────────────────────────────────────────────────────────────────────
# INTERNE HILFSFUNKTIONEN
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_services(technical_json: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalisiert Service-Einträge aus technical_json zu einer einheitlichen Liste."""
    if not technical_json or not isinstance(technical_json, dict):
        return []

    services = technical_json.get("services") or []
    if services:
        return services

    result = []
    for p in technical_json.get("open_ports", []):
        if isinstance(p, dict):
            port = p.get("port")
            svc = p.get("service", {}) if isinstance(p.get("service"), dict) else {}
            product = svc.get("product") or p.get("product")
            version = svc.get("version") or p.get("version")
            cves = p.get("vulnerabilities", []) or svc.get("vulnerabilities", [])
        else:
            port = getattr(p, "port", None)
            product = getattr(p, "product", None)
            version = getattr(p, "version", None)
            cves = getattr(p, "vulnerabilities", []) or []

        result.append({
            "port": port,
            "product": _clean(product),
            "version": _clean(version),
            "cves": cves,
        })
    return result


def _flatten_for_eol(services: List[Dict]) -> List[Dict]:
    """Flacht die verschachtelte Service-Struktur für EOL-Erkennung ab."""
    flat = []
    for s in services:
        if not isinstance(s, dict):
            continue
        sub = s.get("service") or {}
        flat.append({
            "port":    s.get("port"),
            "product": s.get("product") or sub.get("product") or "",
            "version": s.get("version") or sub.get("version") or "",
        })
    return flat


def _clean(value: Optional[str], max_len: int = 80) -> Optional[str]:
    """Bereinigt einen String — entfernt Steuerzeichen, kürzt bei Bedarf."""
    if value is None:
        return None
    s = str(value).strip()
    s = re.sub(r"\s+", " ", s.replace("\n", " ").replace("\r", " "))
    if re.search(r"[A-Za-z0-9+/]{40,}=*", s):
        return "[SSH-Key entfernt]"
    return s[:max_len - 3] + "..." if len(s) > max_len else s


def _detect_scenario(services: List[Dict]) -> Dict[str, Any]:
    """
    Erkennt das primäre Risikoszenario aus den vorhandenen Services.
    Gibt ein Dict mit Flags zurück die die Text-Generierung steuern.
    """
    ports = set()
    products_lower = []

    for s in services:
        p = s.get("port")
        if p:
            ports.add(int(p))
        prod = (s.get("product") or "").lower()
        if prod:
            products_lower.append(prod)

    prod_text = " ".join(products_lower)

    return {
        "has_rdp":      3389 in ports or "rdp" in prod_text or "remote desktop" in prod_text,
        "has_ssh":      22 in ports or "ssh" in prod_text,
        "has_web":      bool(ports & {80, 443, 8080, 8443}) or "http" in prod_text,
        "has_db":       bool(ports & {3306, 5432, 27017, 1433}) or any(k in prod_text for k in ["mysql", "postgres", "mssql", "mongo"]),
        "has_ftp":      bool(ports & {20, 21}) or "ftp" in prod_text,
        "has_vnc":      5900 in ports or "vnc" in prod_text,
        "has_telnet":   23 in ports or "telnet" in prod_text,
        "has_smtp":     25 in ports or "smtp" in prod_text or "mail" in prod_text,
        "port_count":   len(ports),
        "ports":        ports,
    }


def _count_cves(services: List[Dict], technical_json: Optional[Dict]) -> int:
    """Zählt die Gesamtzahl der CVEs aus allen Quellen."""
    ids = set()

    # Aus Services
    for s in services:
        for cv in (s.get("cves") or []):
            cid = cv.get("id") if isinstance(cv, dict) else str(cv)
            if cid:
                ids.add(str(cid))

    # Aus technical_json top-level
    if technical_json:
        for cv in (technical_json.get("vulnerabilities") or technical_json.get("vulns") or []):
            cid = cv.get("id") if isinstance(cv, dict) else str(cv)
            if cid:
                ids.add(str(cid))

    return len(ids)


def _tls_issues(services: List[Dict]) -> List[str]:
    """Gibt eine Liste von TLS-Problemen zurück."""
    issues = []
    for s in services:
        ssl = s.get("ssl_info") or {}
        if isinstance(ssl, dict):
            if ssl.get("expired"):
                issues.append(f"Abgelaufenes Zertifikat auf Port {s.get('port')}")
            if ssl.get("self_signed"):
                issues.append(f"Selbstsigniertes Zertifikat auf Port {s.get('port')}")
            if ssl.get("has_weak_cipher"):
                issues.append(f"Schwache Cipher-Suite auf Port {s.get('port')}")
    return issues


# ─────────────────────────────────────────────────────────────────────────────
# SZENARIO-SPEZIFISCHE TEXTE
# ─────────────────────────────────────────────────────────────────────────────

def _text_rdp(
    cve_count: int,
    port_count: int,
    eol_findings: Optional[List] = None,
    tls_verified_protos: Optional[set] = None,
) -> str:
    """Text für den häufigsten und gefährlichsten Fall: RDP öffentlich exponiert."""
    eol_findings = eol_findings or []
    tls_verified_protos = tls_verified_protos or set()
    eol_systems = [f for f in eol_findings if f.get("eol_status") == "eol"]
    near_eol_systems = [f for f in eol_findings if f.get("eol_status") == "near_eol"]
    has_eol = bool(eol_systems)

    # Combo sentence when RDP + EOL are present together
    if eol_systems:
        names = ", ".join(f.get("display_name", "Unbekannt") for f in eol_systems)
        combo_sentence = (
            f"Das höchste Risiko ist nicht die Anzahl der CVEs, sondern die Kombination "
            f"aus öffentlich erreichbarem RDP und dem nicht mehr unterstützten System "
            f"{names} — dieser Angriffspfad wird aktiv bei Ransomware-Kampagnen ausgenutzt."
        )
    elif near_eol_systems:
        names = ", ".join(f.get("display_name", "Unbekannt") for f in near_eol_systems)
        combo_sentence = (
            f"Hinweis: Das eingesetzte Betriebssystem ({names}) erreicht in Kürze das "
            f"End-of-Life — ein Migrations-Zeitfenster sollte jetzt geplant werden."
        )
    else:
        combo_sentence = ""

    # TLS verified finding sentence (directly observed from TLS handshake)
    if tls_verified_protos:
        protos = ", ".join(sorted(tls_verified_protos))
        tls_sentence = (
            f" Zusätzlich wurden veraltete TLS-Protokolle direkt beobachtet "
            f"(Verified Finding: {protos}) — diese stellen eine kryptographisch überprüfbare "
            f"Schwachstelle dar, unabhängig von Versionsinformationen."
        )
    else:
        tls_sentence = ""

    # CVE note — Inferred findings (version-based, not directly verified)
    if cve_count > 0:
        cve_note = (
            f" Zu den exponierten Diensten wurden {cve_count} potenzielle Schwachstellen "
            f"als Inferred Findings zugeordnet (Zuordnung über Versionserkennung — "
            f"keine direkte Verifikation)."
        )
        if eol_systems:
            names_eol = ", ".join(f.get("display_name", "Unbekannt") for f in eol_systems)
            cve_note += (
                f" Ein Großteil dieser Schwachstellen betrifft direkt {names_eol} — "
                f"strukturell nicht behebbar, solange das System nicht ersetzt wird."
            )
    else:
        cve_note = ""

    # EOL-specific 'Was das bedeutet' addendum
    if eol_systems:
        names = ", ".join(f.get("display_name", "Unbekannt") for f in eol_systems)
        eol_meaning = (
            f" Das eingesetzte Betriebssystem ({names}) erhält keine regulären "
            f"Sicherheitsupdates mehr — bekannte Schwachstellen können daher "
            f"strukturell nicht behoben werden."
        )
        eol_recommendation = (
            f" Das Betriebssystem ({names}) sollte zeitnah auf eine unterstützte "
            f"Version migriert oder bis zur Migration netzwerktechnisch isoliert werden. "
            f"Zeitrahmen Migration: innerhalb von 90 Tagen."
        )
    else:
        eol_meaning = ""
        eol_recommendation = ""

    combo_block = f"\n{combo_sentence}" if combo_sentence else ""
    tls_block = tls_sentence  # inline after CVE note

    return (
        "Gesamteinschätzung:\n"
        "Ein Remote-Desktop-Dienst (RDP, Port 3389) ist direkt aus dem Internet erreichbar. "
        "RDP ist einer der meistgenutzten Angriffsvektoren für Ransomware-Kampagnen und "
        "Brute-Force-Angriffe. Angreifer scannen das Internet automatisiert nach exponierten "
        f"RDP-Diensten — Ihre Infrastruktur ist damit aktiv einem erhöhten Risiko ausgesetzt."
        f"{combo_block}"
        f"{cve_note}"
        f"{tls_block}\n\n"
        "Was das bedeutet:\n"
        "Ohne zusätzliche Zugriffskontrollen (VPN, MFA, IP-Whitelist) kann jeder mit "
        "Internetzugang einen Anmeldeversuch starten."
        f"{eol_meaning} "
        "Erfolgreiche Angriffe führen typischerweise zu vollständiger Systemübernahme, "
        "Datenverschlüsselung (Ransomware) oder Datenexfiltration.\n\n"
        "Empfehlung:\n"
        "RDP-Zugang sofort hinter VPN oder einen dedizierten Jumphost verlagern. "
        "Direkte Erreichbarkeit aus dem Internet deaktivieren. Zeitrahmen: innerhalb von 48 Stunden."
        f"{eol_recommendation}\n"
        "Nächste Schritte: IT-Verantwortliche prüfen Zugangskonfiguration (Owner: IT-Sicherheit)."
    )


def _text_db_exposed(db_type: str, cve_count: int) -> str:
    """Text für exponierte Datenbank-Dienste."""
    cve_note = (
        f" Für die erkannte Datenbankversion wurden {cve_count} bekannte Schwachstellen "
        f"(CVEs) gefunden."
        if cve_count > 0 else ""
    )
    return (
        "Gesamteinschätzung:\n"
        f"Eine {db_type}-Datenbankinstanz ist direkt aus dem Internet erreichbar. "
        "Datenbanken sollten grundsätzlich nicht öffentlich exponiert sein — sie enthalten "
        "typischerweise die sensibelsten Unternehmensdaten."
        f"{cve_note}\n\n"
        "Was das bedeutet:\n"
        "Öffentlich erreichbare Datenbanken sind ein primäres Angriffsziel für automatisierte "
        "Scans, Credential-Stuffing und SQL-Injection-Angriffe. Ein erfolgreicher Angriff "
        "kann zu vollständigem Datenverlust, Datenschutzverletzungen (DSGVO) und erheblichen "
        "Bußgeldern führen.\n\n"
        "Empfehlung:\n"
        "Datenbankzugriff auf interne Netzwerke beschränken. Firewall-Regeln anpassen, "
        "externe Erreichbarkeit deaktivieren. Zeitrahmen: sofort.\n"
        "Nächste Schritte: IT prüft Firewall-Konfiguration und Datenbankzugriffslogs (Owner: IT/DBA)."
    )


def _text_web_with_cves(cve_count: int, critical_cves: int, products: List[str]) -> str:
    """Text für Webserver mit bekannten Schwachstellen."""
    severity = "kritische" if critical_cves >= 3 else "erhöhte"
    product_note = f" (erkannte Software: {', '.join(products[:3])})" if products else ""
    return (
        "Gesamteinschätzung:\n"
        f"Die öffentlich erreichbare Webinfrastruktur{product_note} weist {severity} "
        f"Schwachstellen auf. Es wurden {cve_count} bekannte CVEs identifiziert, "
        f"davon {critical_cves} mit kritischem CVSS-Score (≥9.0).\n\n"
        "Was das bedeutet:\n"
        "CVEs in Webserver-Software können zur Kompromittierung des gesamten Systems führen. "
        "Angreifer nutzen bekannte Schwachstellen oft innerhalb von Stunden nach Veröffentlichung "
        "von Exploits. Veraltete Softwareversionen sind ein häufiger Ausgangspunkt für "
        "Angriffe auf die gesamte Unternehmensinfrastruktur.\n\n"
        "Empfehlung:\n"
        "Betroffene Softwarekomponenten zeitnah auf aktuelle Versionen aktualisieren. "
        "Patch-Management-Prozess etablieren. Zeitrahmen: kritische CVEs innerhalb 7 Tage, "
        "übrige innerhalb 30 Tage.\n"
        "Nächste Schritte: IT-Abteilung prüft und priorisiert Patches (Owner: IT-Betrieb)."
    )


def _text_multiple_services(scenario: Dict, cve_count: int) -> str:
    """Text für komplexe Szenarien mit mehreren exponierten Diensten."""
    service_list = []
    if scenario["has_rdp"]:
        service_list.append("Remote Desktop (RDP)")
    if scenario["has_ssh"]:
        service_list.append("SSH")
    if scenario["has_db"]:
        service_list.append("Datenbankdienst")
    if scenario["has_web"]:
        service_list.append("Webserver")
    if scenario["has_ftp"]:
        service_list.append("FTP")
    if scenario["has_smtp"]:
        service_list.append("Mail-Dienst")

    services_str = ", ".join(service_list) if service_list else f"{scenario['port_count']} Dienste"
    cve_note = f" Zusätzlich wurden {cve_count} bekannte Schwachstellen (CVEs) in den eingesetzten Softwareversionen identifiziert." if cve_count > 0 else ""

    return (
        "Gesamteinschätzung:\n"
        f"Die externe Angriffsfläche umfasst mehrere öffentlich erreichbare Dienste: "
        f"{services_str}.{cve_note} "
        "Jeder öffentlich erreichbare Dienst stellt einen potenziellen Einstiegspunkt dar — "
        "die Kombination mehrerer exponierter Dienste erhöht das Risiko einer erfolgreichen "
        "Kompromittierung erheblich.\n\n"
        "Was das bedeutet:\n"
        "Angreifer nutzen öffentlich verfügbare Informationen (OSINT) um die Angriffsfläche "
        "eines Unternehmens zu kartieren, bevor sie gezielt angreifen. Eine breite externe "
        "Sichtbarkeit erleichtert sowohl gezielte als auch automatisierte Angriffe. "
        "Das Risiko reicht von Datenverlust über Betriebsunterbrechungen bis zu "
        "Compliance-Verstößen (DSGVO, ISO 27001).\n\n"
        "Empfehlung:\n"
        "Alle nicht zwingend öffentlich erreichbaren Dienste hinter VPN oder Firewallregeln "
        "verlagern. Externe Angriffsfläche auf das notwendige Minimum reduzieren. "
        "Zeitrahmen: Priorisierung innerhalb 7 Tage, Umsetzung innerhalb 30 Tage.\n"
        "Nächste Schritte: IT erstellt Maßnahmenplan zur Reduktion der externen Dienste "
        "(Owner: IT-Sicherheit, Deadline: siehe Handlungsempfehlungen)."
    )


def _text_ssh_only(cve_count: int) -> str:
    """Text für den Fall dass primär SSH exponiert ist."""
    cve_note = (
        f" Es wurden zudem {cve_count} bekannte Schwachstellen in den eingesetzten "
        f"Softwareversionen identifiziert."
        if cve_count > 0 else ""
    )
    return (
        "Gesamteinschätzung:\n"
        "Ein SSH-Dienst (Port 22) ist öffentlich aus dem Internet erreichbar."
        f"{cve_note} "
        "SSH ist ein legitimer Administrationsdienst, sollte jedoch nicht direkt aus dem "
        "Internet zugänglich sein, da er ein kontinuierliches Ziel für automatisierte "
        "Brute-Force-Angriffe darstellt.\n\n"
        "Was das bedeutet:\n"
        "Öffentlich erreichbare SSH-Dienste werden von automatisierten Scannern "
        "rund um die Uhr auf schwache Passwörter und bekannte Schwachstellen geprüft. "
        "Ohne starke Authentifizierung (SSH-Keys, MFA) oder Zugangsbeschränkungen besteht "
        "ein erhöhtes Risiko für unbefugte Systemzugriffe.\n\n"
        "Empfehlung:\n"
        "SSH-Zugang auf bekannte IP-Adressen beschränken oder hinter VPN verlagern. "
        "Passwort-Authentifizierung deaktivieren, ausschließlich SSH-Key-Authentifizierung "
        "verwenden. Brute-Force-Schutz (Fail2ban) aktivieren.\n"
        "Nächste Schritte: IT prüft SSH-Konfiguration und Zugriffsregeln (Owner: IT-Betrieb)."
    )


def _text_web_clean(port_count: int) -> str:
    """Text für Webserver ohne kritische Schwachstellen — niedrigstes Risikoszenario."""
    return (
        "Gesamteinschätzung:\n"
        "Die externe Angriffsfläche beschränkt sich auf öffentlich erreichbare Webdienste. "
        "Keine kritischen Schwachstellen oder exponierten Administrationsdienste wurden "
        "in dieser OSINT-Analyse identifiziert.\n\n"
        "Aktuelle Lage:\n"
        "Die externe Sichtbarkeit entspricht einem normalen Betriebszustand für "
        "webbasierte Dienste. Regelmäßige Überprüfungen sind dennoch empfohlen, "
        "da sich die Bedrohungslage und Softwareschwachstellen kontinuierlich verändern.\n\n"
        "Empfehlung:\n"
        "Monatliche Wiederholung der Analyse zur Trendbeobachtung. Sicherheitsheader "
        "und TLS-Konfiguration regelmäßig prüfen.\n"
        "Nächste Schritte: IT prüft TLS-Konfiguration und Security-Header (Owner: IT-Betrieb)."
    )


def _text_critical_generic(cve_count: int, port_count: int) -> str:
    """Fallback-Text für kritische Szenarien die keinem spezifischen Muster entsprechen."""
    cve_note = (
        f" Es wurden {cve_count} bekannte Schwachstellen (CVEs) identifiziert."
        if cve_count > 0 else ""
    )
    return (
        "Gesamteinschätzung:\n"
        f"Die externe Analyse zeigt {port_count} öffentlich erreichbare Dienste mit "
        f"kritischen Risikoindikatoren.{cve_note} "
        "Die Kombination aus exponierten Diensten und bekannten Schwachstellen stellt "
        "ein erhebliches Sicherheitsrisiko dar.\n\n"
        "Was das bedeutet:\n"
        "Öffentlich erreichbare Dienste mit bekannten Schwachstellen sind ein primäres "
        "Angriffsziel. Angreifer nutzen OSINT-Daten um Schwachstellen zu identifizieren "
        "und gezielt auszunutzen — oft vollständig automatisiert.\n\n"
        "Empfehlung:\n"
        "Externe Angriffsfläche sofort bewerten und auf das notwendige Minimum reduzieren. "
        "Kritische CVEs priorisiert patchen. Zeitrahmen: innerhalb 24-48 Stunden einleiten.\n"
        "Nächste Schritte: IT-Sicherheit bewertet alle exponierten Dienste und erstellt "
        "Maßnahmenplan (Owner: IT-Sicherheit/Geschäftsführung)."
    )


def _text_attention(scenario: Dict, cve_count: int) -> str:
    """Text für erhöhtes aber nicht kritisches Risiko."""
    service_hints = []
    if scenario["has_ssh"]:
        service_hints.append("SSH-Zugang überprüfen und absichern")
    if scenario["has_web"] and cve_count > 0:
        service_hints.append(f"Webserver-Software aktualisieren ({cve_count} CVEs bekannt)")
    if scenario["has_smtp"]:
        service_hints.append("Mail-Dienst auf Konfigurationsschwächen prüfen")

    hints_text = (
        "\n\nKonkrete Hinweise:\n" + "\n".join(f"- {h}" for h in service_hints)
        if service_hints else ""
    )

    return (
        "Gesamteinschätzung:\n"
        "Die externe Sicherheitsanalyse zeigt erhöhte Risiken, die zeitnahe Aufmerksamkeit "
        "erfordern, aber keine unmittelbare Notfallreaktion auslösen."
        f"{hints_text}\n\n"
        "Empfehlung:\n"
        "Überprüfung durch IT-Abteilung innerhalb von 14 Tagen. Identifizierte "
        "Schwachstellen beheben und externe Angriffsfläche reduzieren.\n"
        "Nächste Schritte: IT prüft und priorisiert (Owner: IT-Betrieb)."
    )


def _text_monitor(scenario: Dict) -> str:
    """Text für stabile Sicherheitslage — geringster Handlungsbedarf."""
    return (
        "Gesamteinschätzung:\n"
        "Die externe Sicherheitslage Ihrer Infrastruktur wird aktuell als stabil bewertet. "
        "Keine kritischen Schwachstellen oder exponierten Administrationsdienste wurden "
        "in dieser OSINT-Analyse identifiziert.\n\n"
        "Aktuelle Lage:\n"
        "Die öffentliche Sichtbarkeit entspricht einem normalen Betriebszustand. "
        "Regelmäßige Wiederholungen dieser Analyse sind empfohlen, um Veränderungen "
        "der Angriffsfläche frühzeitig zu erkennen.\n\n"
        "Empfehlung:\n"
        "Kein unmittelbarer Handlungsbedarf. Monatliche Wiederholung der Analyse "
        "zur Trendbeobachtung empfohlen.\n"
        "Nächste Schritte: IT plant nächsten Report-Termin (Owner: IT-Betrieb)."
    )


# ─────────────────────────────────────────────────────────────────────────────
# HAUPTFUNKTION — wird vom Runner aufgerufen
# ─────────────────────────────────────────────────────────────────────────────

def generate_management_text(
    business_risk: BusinessRisk,
    evaluation: EvaluationResult,
    technical_json: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generiert einen management-tauglichen Zusammenfassungstext für den Exposure-Report.

    Jedes Risikoszenario erhält einen spezifischen Text mit:
    - Konkreter Beschreibung was gefunden wurde
    - Erklärung was das bedeutet (für Nicht-Techniker)
    - Klarer Handlungsempfehlung mit Zeitrahmen und Verantwortlichkeit

    Args:
        business_risk: BusinessRisk Enum (CRITICAL / ATTENTION / MONITOR)
        evaluation:    EvaluationResult mit critical_points und exposure_score
        technical_json: Technische Daten aus Shodan (Services, CVEs, etc.)

    Returns:
        Fertiger Textblock für die Management-Zusammenfassung im PDF
    """

    services = _normalize_services(technical_json)
    scenario = _detect_scenario(services)
    cve_count = _count_cves(services, technical_json)

    # Produkt-Namen für Webserver-Szenario
    web_products = [
        s.get("product") for s in services
        if s.get("product") and s.get("port") in {80, 443, 8080, 8443}
    ]
    web_products = [p for p in web_products if p]

    # Kritische CVEs zählen (CVSS >= 9.0) aus enriched Daten wenn vorhanden
    critical_cves = 0
    if technical_json and isinstance(technical_json, dict):
        for cv in (technical_json.get("cve_enriched") or []):
            try:
                cvss = float(cv.get("cvss") or 0)
                if cvss >= 9.0:
                    critical_cves += 1
            except Exception:
                continue

    # ── KRITISCH ──────────────────────────────────────────────────────────────
    if business_risk == BusinessRisk.CRITICAL:

        # Szenario 1: RDP exponiert — häufigster und gefährlichster Fall
        if scenario["has_rdp"]:
            eol_findings = []
            if _scan_eol:
                try:
                    flat = _flatten_for_eol(services)
                    eol_findings = _scan_eol(flat)
                except Exception:
                    pass
            # Detect enabled insecure TLS protocols (Verified Findings)
            _tls_insecure_vers = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
            tls_verified_protos: set = set()
            for _s in services:
                _ssl = _s.get("ssl_info") or {} if isinstance(_s, dict) else {}
                if isinstance(_ssl, dict):
                    for _v in (_ssl.get("versions") or []):
                        _vs = str(_v).strip()
                        if not _vs.startswith("-") and _vs in _tls_insecure_vers:
                            tls_verified_protos.add(_vs)
            return _text_rdp(cve_count, scenario["port_count"], eol_findings, tls_verified_protos)

        # Szenario 2: Datenbank exponiert
        if scenario["has_db"]:
            db_type = "MySQL" if any("mysql" in (s.get("product") or "").lower() for s in services) else \
                      "PostgreSQL" if any("postgres" in (s.get("product") or "").lower() for s in services) else \
                      "Datenbank"
            return _text_db_exposed(db_type, cve_count)

        # Szenario 3: Webserver mit vielen CVEs
        if scenario["has_web"] and cve_count > 5:
            return _text_web_with_cves(cve_count, critical_cves, web_products)

        # Szenario 4: Mehrere exponierte Dienste
        if scenario["port_count"] >= 3 or (scenario["has_ssh"] and scenario["has_web"]):
            return _text_multiple_services(scenario, cve_count)

        # Szenario 5: Nur SSH
        if scenario["has_ssh"] and not scenario["has_web"]:
            return _text_ssh_only(cve_count)

        # Fallback kritisch
        return _text_critical_generic(cve_count, scenario["port_count"])

    # ── ATTENTION ─────────────────────────────────────────────────────────────
    if business_risk == BusinessRisk.ATTENTION:
        return _text_attention(scenario, cve_count)

    # ── MONITOR ───────────────────────────────────────────────────────────────
    # Webserver ohne kritische Befunde
    if scenario["has_web"] and not scenario["has_rdp"] and not scenario["has_db"] and cve_count == 0:
        return _text_web_clean(scenario["port_count"])

    return _text_monitor(scenario)