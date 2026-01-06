from shodan_report.models import AssetSnapshot
from shodan_report.persistence.snapshot_manager import compare_snapshots

def analyze_trend(prev_snapshot: AssetSnapshot, current_snapshot: AssetSnapshot) -> str:
    """
    Analysiert die Veränderungen zwischen zwei AssetSnapshots und gibt eine Trendbeschreibung zurück.
    """

    changes = compare_snapshots(prev_snapshot, current_snapshot)
    trend_lines = []

    if changes["new_ports"]:
        trend_lines.append(f"Neue offene Ports: {', '.join(map(str, changes['new_ports']))}")

    if changes["removed_ports"]:
        trend_lines.append(f"Geschlossene Ports: {', '.join(map(str, changes['removed_ports']))}")

    if changes["new_services"]:
        trend_lines.append(f"Neu entdeckte Dienste: {', '.join(changes['new_services'])}")

    if changes["removed_services"]:
        trend_lines.append(f"Entfernte Dienste: {', '.join(changes['removed_services'])}")


    if not trend_lines:
        return "Keine signifikanten Veränderungen im Vergleich zum vorherigen Snapshot."

    return "\n".join(trend_lines)