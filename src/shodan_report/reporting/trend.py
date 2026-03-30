# reporting/trend.py
# ─────────────────────────────────────────────────────────────────────────────
# Trend-Analyse Logik — vergleicht zwei Snapshots und generiert
# einen strukturierten Trendtext für das PDF.
# ─────────────────────────────────────────────────────────────────────────────

from shodan_report.models import AssetSnapshot
from shodan_report.persistence.snapshot_manager import compare_snapshots
from shodan_report.evaluation.helpers.eval_helpers import (
    analyze_open_ports,
    analyze_services,
)


def _rating_text(prev: int, curr: int, higher_is_worse: bool = True) -> str:
    diff = curr - prev
    if diff == 0:
        return "→ unverändert"
    if diff > 0:
        if higher_is_worse:
            return "↑ leicht verschlechtert" if diff == 1 else "↑↑ verschlechtert"
        else:
            return "↓ leicht verbessert" if diff == 1 else "↓↓ verbessert"
    else:
        if higher_is_worse:
            return "↓ leicht verbessert" if diff == -1 else "↓↓ verbessert"
        else:
            return "↑ leicht verschlechtert" if diff == -1 else "↑↑ verschlechtert"


def analyze_trend(prev_snapshot: AssetSnapshot, current_snapshot: AssetSnapshot) -> str:
    """
    Erzeugt einen kompakten Trendtext mit Tabelle und Interpretation.
    Wird vom Runner aufgerufen wenn ein Vormonat-Snapshot vorhanden ist.
    """
    prev_ports = len(getattr(prev_snapshot, "open_ports", []) or [])
    curr_ports = len(getattr(current_snapshot, "open_ports", []) or [])

    _, prev_svc_findings = analyze_services(prev_snapshot.services or [])
    _, curr_svc_findings = analyze_services(current_snapshot.services or [])

    def _count_critical(findings):
        keys = ["rdp", "vnc", "telnet", "kritischer dienst", "datenbank", "ssh"]
        return sum(1 for f in findings if any(k in f.lower() for k in keys))

    prev_crit = _count_critical(prev_svc_findings)
    curr_crit = _count_critical(curr_svc_findings)

    prev_cves = len(set(getattr(prev_snapshot, "vulns", []) or []))
    curr_cves = len(set(getattr(current_snapshot, "vulns", []) or []))

    tls_ports = {443, 8443, 9443}

    def _tls_issues(snapshot):
        issues = 0
        for s in snapshot.services or []:
            try:
                port = getattr(s, "port", None)
                ssl = getattr(s, "ssl_info", None)
            except Exception:
                port = None
                ssl = None
            if port in tls_ports and not ssl:
                issues += 1
        return issues

    prev_tls = _tls_issues(prev_snapshot)
    curr_tls = _tls_issues(current_snapshot)

    diffs = compare_snapshots(prev_snapshot, current_snapshot)

    # Keine Veränderungen
    if not any(diffs.get(k) for k in ("new_ports", "removed_ports", "new_services", "removed_services")):
        if prev_ports == curr_ports and prev_crit == curr_crit and prev_cves == curr_cves and prev_tls == curr_tls:
            return "Keine signifikanten Veränderungen im Vergleich zum vorherigen Snapshot."

    header = "Veränderung zur Vormonatsanalyse\n\nKategorie\tVormonat\tAktuell\tBewertung\n"

    rows = [
        f"Öffentliche Ports\t{prev_ports}\t{curr_ports}\t{_rating_text(prev_ports, curr_ports)}",
        f"Kritische Services\t{prev_crit}\t{curr_crit}\t{_rating_text(prev_crit, curr_crit)}",
        f"Hochrisiko-CVEs\t{prev_cves}\t{curr_cves}\t{_rating_text(prev_cves, curr_cves)}",
        f"TLS-Schwächen\t{prev_tls}\t{curr_tls}\t{_rating_text(prev_tls, curr_tls)}",
    ]

    change_lines = []
    new_ports = diffs.get("new_ports", []) or []
    removed_ports = diffs.get("removed_ports", []) or []
    new_services = diffs.get("new_services", []) or []
    removed_services = diffs.get("removed_services", []) or []

    if new_ports:
        change_lines.append("Neue offene Ports: " + ", ".join(str(p) for p in new_ports))
    if removed_ports:
        change_lines.append("Geschlossene Ports: " + ", ".join(str(p) for p in removed_ports))
    if new_services:
        change_lines.append("Neu entdeckte Dienste: " + ", ".join(s for s in new_services))
    if removed_services:
        change_lines.append("Entfernte Dienste: " + ", ".join(s for s in removed_services))

    # Interpretation mit mehr Kontext
    if curr_tls > prev_tls:
        interp = (
            "\nInterpretation: Die Angriffsfläche ist stabil; "
            "leichte Verschlechterung in der Kryptokonfiguration erkannt. "
            "TLS-Zertifikate und Cipher-Suites sollten zeitnah geprüft werden."
        )
    elif curr_cves > prev_cves:
        delta = curr_cves - prev_cves
        interp = (
            f"\nInterpretation: Die Anzahl bekannter Schwachstellen ist um {delta} gestiegen. "
            "Dies kann auf neu veröffentlichte CVEs für die eingesetzte Software hinweisen. "
            "Patches und Updates werden empfohlen."
        )
    elif curr_crit > prev_crit:
        interp = (
            "\nInterpretation: Ein zusätzlicher kritischer Administrationsdienst wurde identifiziert. "
            "Die externe Angriffsfläche hat sich erhöht — Härtungsmaßnahmen empfohlen."
        )
    elif curr_ports > prev_ports:
        delta = curr_ports - prev_ports
        interp = (
            f"\nInterpretation: {delta} neuer öffentlich erreichbarer Dienst wurde identifiziert. "
            "Überprüfen Sie ob dieser Dienst absichtlich exponiert ist."
        )
    elif curr_ports < prev_ports or curr_crit < prev_crit or curr_cves < prev_cves:
        interp = (
            "\nInterpretation: Die externe Angriffsfläche hat sich im Vergleich zum Vormonat "
            "verbessert. Umgesetzte Maßnahmen zeigen Wirkung."
        )
    else:
        interp = "\nInterpretation: Die Angriffsfläche ist stabil. Keine signifikanten Veränderungen."

    change_block = "\n".join(change_lines)
    if change_block:
        return change_block + "\n\n" + header + "\n".join(rows) + interp
    return header + "\n".join(rows) + interp