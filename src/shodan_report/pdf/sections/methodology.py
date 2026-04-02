"""Einordnung & Bewertungslogik — letzte Seite des Reports."""

from typing import List, Dict, Any
from reportlab.platypus import Paragraph, Spacer, HRFlowable


def _h2(text: str, styles: Dict) -> Paragraph:
    return Paragraph(text, styles.get("heading2") or styles.get("normal"))


def _body(text: str, styles: Dict) -> Paragraph:
    return Paragraph(text, styles.get("methodology_body") or styles.get("normal"))


def _bullet(text: str, styles: Dict) -> Paragraph:
    return Paragraph(
        f"• {text}",
        styles.get("methodology_bullet") or styles.get("bullet") or styles.get("normal"),
    )


def _divider() -> HRFlowable:
    return HRFlowable(width="100%", thickness=0.5, color="#e2e8f0", spaceAfter=4, spaceBefore=4)


def create_methodology_section(elements: List[Any], styles: Dict[str, Any], *args, **kwargs) -> None:
    """Rendert die 'Einordnung & Bewertungslogik'-Seite als letzten Abschnitt des Reports."""

    h1 = styles.get("heading1") or styles.get("heading2") or styles.get("normal")

    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Einordnung & Bewertungslogik", h1))
    elements.append(Spacer(1, 3))
    elements.append(_body(
        "Datenbasis: ausschließlich OSINT (öffentlich zugängliche Informationen) — "
        "keine aktiven Scans, keine internen Systeme, keine Authentifizierung.",
        styles,
    ))

    # ── Begriffe ─────────────────────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("Begriffe", styles))

    glossary = [
        ("IP-Adresse (analysiertes Asset)", "Der konkrete Untersuchungsgegenstand: eine öffentlich erreichbare IPv4-Adresse. Hostnamen und Domains sind dieser IP zugeordnete Netzwerk-Identitäten — sie liefern Kontext, werden aber nicht als eigenständige Assets bewertet."),
        ("Verified Finding",  "Direkt beobachtetes Faktum — z. B. aktives TLS-Protokoll, offener Port. Kein Schluss, sondern Messwert."),
        ("Inferred Finding",  "Abgeleitete Erkenntnis via Versionserkennung — z. B. mögliche CVEs. Nicht aktiv verifiziert."),
        ("CVE / CVSS",        "Dokumentierte Schwachstelle (CVE) mit Schwerebewertung 0–10 (CVSS)."),
        ("EOL (End of Life)", "Software ohne Sicherheits-Support — strukturell nicht mehr patchbar."),
        ("RDP",               "Remote Desktop Protocol — häufigster Angriffsvektor für Ransomware-Kampagnen."),
        ("TLS",               "Transport Layer Security — Standard für verschlüsselte Kommunikation."),
    ]
    for term, desc in glossary:
        elements.append(_body(f"<b>{term}:</b> {desc}", styles))
        elements.append(Spacer(1, 1))

    # ── Exposure-Level ───────────────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("Exposure-Level (1–5)", styles))
    elements.append(_body(
        "Aggregierte Risikoabschätzung basierend auf: Anzahl öffentlicher Dienste, "
        "kritische Services (RDP, SSH, Datenbank), CVE-Indikatoren. "
        "<b>Keine absolute Messung</b> — interne Kontrollen (Firewall, MFA) fließen nicht ein.",
        styles,
    ))

    # ── EOL ──────────────────────────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("EOL-Systeme", styles))
    for item in [
        "Keine Sicherheitsupdates mehr vom Hersteller",
        "Bekannte Schwachstellen strukturell nicht schließbar — dauerhaftes Risiko",
    ]:
        elements.append(_bullet(item, styles))

    # ── Attack Surface Discovery ──────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("Attack Surface Discovery (Abschnitt 3)", styles))
    elements.append(_body(
        "Sofern eine Domain analysiert wurde, ermittelt das System automatisch alle "
        "öffentlich erreichbaren IP-Adressen via passivem OSINT — ausschließlich aus bereits "
        "öffentlich verfügbaren Quellen, ohne aktive Scans oder Verbindungsaufbau zum Kundensystem.",
        styles,
    ))
    elements.append(Spacer(1, 2))
    for item in [
        "<b>DNS A-Records:</b> Direkte IP-Auflösung der Domain und www-Subdomain",
        "<b>MX-Records:</b> Mailserver-IPs — häufig direkt exponiert, selten in Sicherheitsanalysen berücksichtigt",
        "<b>NS-Records:</b> Nameserver-IPs des Hostinganbieters",
        "<b>crt.sh (Zertifikats-Historie):</b> Alle jemals ausgestellten TLS-Zertifikate der Domain — "
        "enthüllt vergessene Subdomains und historische Infrastruktur",
        "<b>HackerTarget API:</b> Passiver Subdomain-Lookup aus öffentlichen DNS-Datenbanken",
        "<b>CDN-Erkennung:</b> IPs in bekannten Cloudflare-, Akamai-, Fastly- und AWS CloudFront-Ranges "
        "werden automatisch gefiltert — der eigentliche Server ist dahinter verborgen",
    ]:
        elements.append(_bullet(item, styles))
    elements.append(Spacer(1, 2))
    elements.append(_body(
        "Die <b>primäre Analyse-IP</b> (das zu bewertende Asset) wird automatisch nach folgender Priorität gewählt: "
        "A-Record der Hauptdomain → A-Record von www → Mailserver → erste gefundene IP. "
        "Alle übrigen IPs und Hostnamen werden als <b>weitere Netzwerk-Identitäten</b> in Abschnitt 3 aufgeführt, "
        "aber nicht separat von Shodan bewertet. "
        "Bei Bedarf kann die primäre IP manuell überschrieben werden.",
        styles,
    ))

    # ── Grenzen & Hinweis ────────────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("Grenzen & Hinweis", styles))
    for item in [
        "Momentaufnahme — Lage kann sich täglich ändern",
        "Keine interne Netzwerksicht, keine Garantie auf Vollständigkeit",
        "CVE-Zuordnungen via Versionserkennung (Inferred) — keine aktive Verifikation",
        "Attack Surface Discovery erhebt ausschließlich öffentlich indexierte Daten — "
        "kein Verbindungsaufbau zum Kundensystem, kein aktiver Scan",
    ]:
        elements.append(_bullet(item, styles))
    elements.append(Spacer(1, 4))
    elements.append(_body(
        "<b>Dieser Bericht ersetzt keinen Penetrationstest oder eine interne Sicherheitsüberprüfung.</b>",
        styles,
    ))
