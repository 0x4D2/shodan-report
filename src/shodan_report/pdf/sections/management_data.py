from typing import Any, Dict, List


def prepare_management_data(technical_json: Dict[str, Any], evaluation: Any) -> Dict[str, Any]:
    """Extract canonical management-related metrics from raw snapshot and evaluation.

    Returns a dict containing keys used by the rendering section such as:
    - exposure_score, exposure_display, risk_level
    - critical_points, critical_points_count, cves
    - total_ports, cve_count, unique_cves, service_rows, top_vulns
    """
    # Exposure / risk fields
    if isinstance(evaluation, dict):
        exposure_score = evaluation.get("exposure_score", 1)
        exposure_display = evaluation.get("exposure_level", f"{exposure_score}/5")

        risk_level_raw = evaluation.get("risk", "low")
        if isinstance(risk_level_raw, str):
            risk_level = risk_level_raw.lower()
            if "risklevel." in risk_level:
                risk_level = risk_level.replace("risklevel.", "")
        else:
            risk_level = str(risk_level_raw).lower()
            if "risklevel." in risk_level:
                risk_level = risk_level.replace("risklevel.", "")

        critical_points = evaluation.get("critical_points", [])
        critical_points_count = evaluation.get("critical_points_count", 0)
        cves = evaluation.get("cves", [])

    else:
        exposure_score = getattr(evaluation, "exposure_score", 1)
        exposure_display = f"{exposure_score}/5"

        risk_level_raw = getattr(evaluation, "risk", "low")
        if hasattr(risk_level_raw, "value"):
            risk_level = risk_level_raw.value.lower()
        elif hasattr(risk_level_raw, "name"):
            risk_level = risk_level_raw.name.lower()
        else:
            risk_level = str(risk_level_raw).lower()
            if "risklevel." in risk_level:
                risk_level = risk_level.replace("risklevel.", "")

        critical_points = getattr(evaluation, "critical_points", [])
        critical_points_count = len(critical_points)
        cves = getattr(evaluation, "cves", [])

    # Technical summary: ports and vulnerabilities
    if isinstance(technical_json, dict):
        open_ports = technical_json.get("open_ports", [])
        top_vulns = technical_json.get("vulns") or technical_json.get("vulnerabilities") or []
    else:
        open_ports = getattr(technical_json, "open_ports", [])
        top_vulns = getattr(technical_json, "vulns", []) or getattr(technical_json, "vulnerabilities", []) or []

    total_ports = len(open_ports) if open_ports else 0

    eval_cves = []
    if isinstance(evaluation, dict):
        eval_cves = evaluation.get("cves", []) or []
    else:
        eval_cves = getattr(evaluation, "cves", []) or []

    unique_cves = set()
    for v in list(top_vulns) + list(eval_cves):
        unique_cves.add(str(v))

    # include per-service vulnerabilities if present
    try:
        for svc in open_ports or []:
            if isinstance(svc, dict):
                sv_vulns = svc.get("vulnerabilities") or svc.get("_cves") or svc.get("vulns") or []
            else:
                sv_vulns = getattr(svc, "vulnerabilities", []) or getattr(svc, "_cves", []) or getattr(svc, "vulns", []) or []
            for vv in sv_vulns:
                unique_cves.add(str(vv))
    except Exception:
        pass

    cve_count = len(unique_cves)

    # return deterministic list for tests/consumers
    unique_cves_list = sorted(unique_cves)

    # service summary helper data (kept minimal here; renderer can call helpers)
    service_rows: List = []
    try:
        from shodan_report.pdf.helpers.management_helpers import _build_service_summary

        service_rows = _build_service_summary(technical_json)
    except Exception:
        service_rows = []

    return {
        "exposure_score": exposure_score,
        "exposure_display": exposure_display,
        "risk_level": risk_level,
        "critical_points": critical_points,
        "critical_points_count": critical_points_count,
        "cves": cves,
        "total_ports": total_ports,
        "cve_count": cve_count,
        "unique_cves": unique_cves_list,
        "service_rows": service_rows,
        "top_vulns": top_vulns,
    }
