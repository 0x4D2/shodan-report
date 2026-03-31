"""Einordnung & Bewertungslogik — letzte Seite des Reports."""

from typing import List, Dict, Any
from reportlab.platypus import Paragraph, Spacer, HRFlowable


def _h2(text: str, styles: Dict) -> Paragraph:
    return Paragraph(text, styles.get("heading2") or styles.get("normal"))


def _body(text: str, styles: Dict) -> Paragraph:
    return Paragraph(text, styles.get("normal"))


def _bullet(text: str, styles: Dict) -> Paragraph:
    return Paragraph(f"• {text}", styles.get("bullet") or styles.get("normal"))


def _divider() -> HRFlowable:
    return HRFlowable(width="100%", thickness=0.5, color="#e2e8f0", spaceAfter=5, spaceBefore=5)


def create_methodology_section(elements: List[Any], styles: Dict[str, Any], *args, **kwargs) -> None:
    """Rendert die 'Einordnung & Bewertungslogik'-Seite als letzten Abschnitt des Reports."""

    h1 = styles.get("heading1") or styles.get("heading2") or styles.get("normal")

    elements.append(Spacer(1, 18))
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
        ("Verified Finding",   "Direkt beobachtetes Faktum — z. B. aktives TLS-Protokoll, offener Port. Kein Schluss, sondern Messwert."),
        ("Inferred Finding",   "Abgeleitete Erkenntnis via Versionserkennung — z. B. mögliche CVEs. Nicht aktiv verifiziert."),
        ("CVE / CVSS",         "Dokumentierte Schwachstelle (CVE) mit Schwerebewertung 0–10 (CVSS)."),
        ("EOL (End of Life)",  "Software ohne Sicherheits-Support — strukturell nicht mehr patchbar."),
        ("RDP",                "Remote Desktop Protocol — häufigster Angriffsvektor für Ransomware-Kampagnen."),
        ("TLS",                "Transport Layer Security — Standard für verschlüsselte Kommunikation."),
    ]
    for term, desc in glossary:
        elements.append(_body(f"<b>{term}:</b> {desc}", styles))
        elements.append(Spacer(1, 2))

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
        "Bekannte Schwachstellen strukturell nicht schließbar",
        "Dauerhaftes, nicht patch-bares Risiko — gezielt für Angriffe genutzt",
    ]:
        elements.append(_bullet(item, styles))

    # ── Grenzen ──────────────────────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("Grenzen & Hinweis", styles))
    for item in [
        "Momentaufnahme — Lage kann sich täglich ändern",
        "Keine interne Netzwerksicht, keine Garantie auf Vollständigkeit",
        "CVE-Zuordnungen via Versionserkennung (Inferred) — keine aktive Verifikation",
    ]:
        elements.append(_bullet(item, styles))
    elements.append(Spacer(1, 4))
    elements.append(_body(
        "<b>Dieser Bericht ersetzt keinen Penetrationstest oder eine interne Sicherheitsüberprüfung.</b>",
        styles,
    ))

    elements.append(Spacer(1, 12))
    elements.append(_divider())
    elements.append(_body(
        "<i>Ende des Dokuments.</i>",
        styles,
    ))

from typing import List, Dict, Any
from reportlab.platypus import Paragraph, Spacer, HRFlowable


def _h2(text: str, styles: Dict) -> Paragraph:
    return Paragraph(text, styles.get("heading2") or styles.get("normal"))


def _h3(text: str, styles: Dict) -> Paragraph:
    return Paragraph(text, styles.get("heading3") or styles.get("normal"))


def _body(text: str, styles: Dict) -> Paragraph:
    return Paragraph(text, styles.get("normal"))


def _bullet(text: str, styles: Dict) -> Paragraph:
    return Paragraph(f"• {text}", styles.get("bullet") or styles.get("normal"))


def _divider() -> HRFlowable:
    return HRFlowable(width="100%", thickness=0.5, color="#e2e8f0", spaceAfter=6, spaceBefore=6)


def create_methodology_section(elements: List[Any], styles: Dict[str, Any], *args, **kwargs) -> None:
    """Rendert die 'Einordnung & Bewertungslogik'-Seite als letzten Abschnitt des Reports."""

    h1 = styles.get("heading1") or styles.get("heading2") or styles.get("normal")

    elements.append(Spacer(1, 18))
    elements.append(Paragraph("Einordnung & Bewertungslogik", h1))
    elements.append(Spacer(1, 4))
    elements.append(_body(
        "Diese Seite erklärt die Methodik und Begriffe dieses Berichts. "
        "Sie dient dazu, die Ergebnisse korrekt einzuordnen und die Bewertungslogik nachvollziehbar zu machen.",
        styles,
    ))

    # ── Datenbasis ───────────────────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("Datenbasis", styles))
    elements.append(_body(
        "Dieser Bericht basiert ausschließlich auf <b>OSINT (Open Source Intelligence)</b> — "
        "öffentlich zugänglichen Informationen. Er zeigt die externe Angriffsfläche, "
        "wie sie auch potenzielle Angreifer sehen können.",
        styles,
    ))
    elements.append(Spacer(1, 4))
    for item in [
        "Keine Analyse interner Systeme",
        "Keine aktiven Angriffe oder Exploit-Versuche",
        "Keine Verwendung von Authentifizierungsdaten",
    ]:
        elements.append(_bullet(item, styles))

    # ── Begriffserklärungen ──────────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("Begriffserklärungen", styles))

    glossary = [
        ("OSINT",               "Öffentlich verfügbare Informationen aus technischen Quellen."),
        ("Verified Finding",    "Direkt beobachtetes technisches Faktum — z. B. aktives TLS-Protokoll, offener Port, "
                                "Zertifikat. Keine Schlussfolgerung, sondern direkter Messwert."),
        ("Inferred Finding",    "Abgeleitete Erkenntnis auf Basis erkannter Versionen — z. B. mögliche CVEs. "
                                "Nicht aktiv verifiziert; Zuordnung über öffentliche Datenbanken (NVD)."),
        ("CVE",                 "Common Vulnerabilities and Exposures — öffentlich dokumentierte Sicherheitslücke in Software."),
        ("CVSS",                "Common Vulnerability Scoring System — Schwere einer Schwachstelle, Skala 0–10."),
        ("TLS",                 "Transport Layer Security — Standard für verschlüsselte Netzwerkkommunikation."),
        ("RDP",                 "Remote Desktop Protocol — Microsofts Protokoll für Remote-Zugriff auf Windows-Systeme."),
        ("EOL (End of Life)",   "Software ohne aktiven Hersteller-Support — erhält keine Sicherheitsupdates mehr."),
    ]
    for term, desc in glossary:
        elements.append(_body(f"<b>{term}:</b> {desc}", styles))
        elements.append(Spacer(1, 3))

    # ── Exposure-Level ───────────────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("Exposure-Level (1–5)", styles))
    elements.append(_body(
        "Der Exposure-Level ist eine aggregierte Risikoabschätzung der externen Angriffsfläche. "
        "Er basiert auf:",
        styles,
    ))
    elements.append(Spacer(1, 4))
    for item in [
        "Anzahl öffentlich erreichbarer Dienste",
        "Vorhandensein kritischer Services (z. B. RDP, SSH, Datenbank)",
        "Hinweise auf bekannte Schwachstellen (CVE-Indikatoren)",
    ]:
        elements.append(_bullet(item, styles))
    elements.append(Spacer(1, 4))
    elements.append(_body(
        "<b>Wichtig:</b> Diese Bewertung ist keine absolute Messung, sondern eine Priorisierungshilfe "
        "auf Basis externer OSINT-Daten. Interne Kontrollen (Firewall, MFA, Monitoring) "
        "werden nicht berücksichtigt.",
        styles,
    ))

    # ── EOL ──────────────────────────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("EOL-Systeme", styles))
    for item in [
        "Kein aktiver Hersteller-Support mehr — keine Sicherheitsupdates",
        "Bekannte Schwachstellen strukturell nicht behebbar — dauerhaftes Risiko",
    ]:
        elements.append(_bullet(item, styles))

    # ── Grenzen & Hinweis ────────────────────────────────────────────────────
    elements.append(_divider())
    elements.append(_h2("Grenzen & Hinweis", styles))
    for item in [
        "Passive Datenerhebung — keine aktiven Scans, keine interne Netzwerksicht",
        "Momentaufnahme: Lage kann sich täglich ändern; CVE-Zuordnung via Versionserkennung (Inferred)",
        "Ersetzt keinen Penetrationstest oder eine interne Sicherheitsüberprüfung",
    ]:
        elements.append(_bullet(item, styles))
    elements.append(Spacer(1, 8))
