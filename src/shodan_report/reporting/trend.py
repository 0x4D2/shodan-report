from shodan_report.models import AssetSnapshot
from shodan_report.persistence.snapshot_manager import compare_snapshots
from shodan_report.evaluation.helpers.eval_helpers import (
    analyze_open_ports,
    analyze_services,
)


def _rating_text(prev: int, curr: int, higher_is_worse: bool = True) -> str:
    # Return a short arrow-based rating and a one-word description.
    diff = curr - prev
    if diff == 0:
        return "→ unverändert"
    if diff > 0:
        # increase: worse when higher_is_worse
        if higher_is_worse:
            return "↑ leicht" if diff == 1 else "↑↑ verschlechtert"
        else:
            return "↓ leicht" if diff == 1 else "↓↓ verbessert"
    else:
        # decrease
        if higher_is_worse:
            return "↓ leicht" if diff == -1 else "↓↓ verbessert"
        else:
            return "↑ leicht" if diff == -1 else "↑↑ verschlechtert"


def analyze_trend(prev_snapshot: AssetSnapshot, current_snapshot: AssetSnapshot) -> str:
    """
    Produce a compact German trend summary table and a short interpretation.

    The table contains: Kategorie | Vormonat | Aktuell | Bewertung
    """
    # Counts
    prev_ports = len(getattr(prev_snapshot, "open_ports", []) or [])
    curr_ports = len(getattr(current_snapshot, "open_ports", []) or [])

    # Critical services: use analyze_services findings and count entries
    _, prev_svc_findings = analyze_services(prev_snapshot.services or [])
    _, curr_svc_findings = analyze_services(current_snapshot.services or [])

    def _count_critical(findings):
        keys = ["rdp", "vnc", "telnet", "kritischer dienst", "datenbank", "ssh"]
        return sum(1 for f in findings if any(k in f.lower() for k in keys))

    prev_crit = _count_critical(prev_svc_findings)
    curr_crit = _count_critical(curr_svc_findings)

    # High-risk CVEs: fallback to counting listed vulns
    prev_cves = len(set(getattr(prev_snapshot, "vulns", []) or []))
    curr_cves = len(set(getattr(current_snapshot, "vulns", []) or []))

    # TLS weaknesses: heuristic: count TLS/HTTPS ports without ssl_info
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

    # Compare snapshots for explicit new/removed ports and services
    diffs = compare_snapshots(prev_snapshot, current_snapshot)

    # If there are no diffs at all and no metric changes, return a short message expected by callers/tests
    if not any(diffs.get(k) for k in ("new_ports", "removed_ports", "new_services", "removed_services")):
        if prev_ports == curr_ports and prev_crit == curr_crit and prev_cves == curr_cves and prev_tls == curr_tls:
            return "Keine signifikanten Veränderungen im Vergleich zum vorherigen Snapshot."

    # Build compact table lines (tab-separated so PDF renderer can keep compact)
    header = "Veränderung zur Vormonatsanalyse\n\nKategorie\tVormonat\tAktuell\tBewertung\n"

    rows = []
    rows.append(f"Öffentliche Ports\t{prev_ports}\t{curr_ports}\t{_rating_text(prev_ports, curr_ports)}")
    rows.append(f"Kritische Services\t{prev_crit}\t{curr_crit}\t{_rating_text(prev_crit, curr_crit)}")
    rows.append(f"Hochrisiko-CVEs\t{prev_cves}\t{curr_cves}\t{_rating_text(prev_cves, curr_cves)}")
    rows.append(f"TLS-Schwächen\t{prev_tls}\t{curr_tls}\t{_rating_text(prev_tls, curr_tls)}")

    # Build short change summary lines for human readers (e.g. "Neue offene Ports: 443")
    change_lines = []
    new_ports = diffs.get("new_ports", []) or []
    removed_ports = diffs.get("removed_ports", []) or []
    new_services = diffs.get("new_services", []) or []
    removed_services = diffs.get("removed_services", []) or []

    if new_ports:
        change_lines.append("Neue offene Ports: " + ", ".join(str(p) for p in new_ports))
    if removed_ports:
        change_lines.append("Geschlossene Ports: " + ", ".join(str(p) for p in removed_ports))
    # For services keep names as given; allow empty names to show header only
    if new_services is not None:
        change_lines.append("Neu entdeckte Dienste: " + ", ".join(s for s in new_services))
    if removed_services:
        change_lines.append("Entfernte Dienste: " + ", ".join(s for s in removed_services))

    # Short single-line interpretation (compact)
    if curr_tls > prev_tls:
        interp = (
            "\nInterpretation: Die Angriffsfläche ist stabil; leichte Verschlechterung in der Kryptokonfiguration."
        )
    elif curr_tls < prev_tls and prev_ports == curr_ports and prev_crit == curr_crit and prev_cves == curr_cves:
        interp = (
            "\nInterpretation: TLS-Schwächen wurden behoben; keine Zunahme bei öffentlichen Managementdiensten "
            "(Management-/Administrationsdienste); Gesamtstruktur unverändert."
        )
    elif curr_cves > prev_cves:
        interp = "\nInterpretation: Anzahl hochriskanter Schwachstellen gestiegen; Patches empfohlen."
    else:
        interp = "\nInterpretation: Angriffsfläche stabil."

    # Prepend change summary lines before the table
    change_block = "\n".join(change_lines)
    if change_block:
        return change_block + "\n\n" + header + "\n".join(rows) + interp
    return header + "\n".join(rows) + interp
