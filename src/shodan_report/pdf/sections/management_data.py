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

    def _normalize_cve_id(x):
        # try to extract canonical CVE id from common shapes
        try:
            if x is None:
                return None
            if isinstance(x, str):
                return x.strip()
            if isinstance(x, dict):
                return (x.get("id") or x.get("cve") or x.get("CVE") or x.get("name") or str(x)).strip()
            # fallback to attribute access
            cid = getattr(x, "id", None) or getattr(x, "cve", None) or None
            return str(cid).strip() if cid is not None else str(x)
        except Exception:
            return str(x)

    unique_cves = set()
    # top-level vulnerabilites
    for v in list(top_vulns) + list(eval_cves):
        nid = _normalize_cve_id(v)
        if nid:
            unique_cves.add(nid)

    # include per-service vulnerabilities and build per-service attribution
    per_service = []
    try:
        for svc in open_ports or []:
            if isinstance(svc, dict):
                sv_vulns = svc.get("vulnerabilities") or svc.get("_cves") or svc.get("vulns") or []
                port = svc.get("port")
                prod = svc.get("product") or (svc.get("service") if isinstance(svc.get("service"), str) else "")
            else:
                sv_vulns = getattr(svc, "vulnerabilities", []) or getattr(svc, "_cves", []) or getattr(svc, "vulns", []) or []
                port = getattr(svc, "port", None)
                prod = getattr(svc, "product", "")

            svc_cves = []
            high_cvss = 0
            for vv in sv_vulns:
                nid = _normalize_cve_id(vv)
                if nid:
                    unique_cves.add(nid)
                    svc_cves.append(nid)
                # count high CVSS if present
                try:
                    cvss = None
                    if isinstance(vv, dict):
                        cvss = vv.get("cvss") or vv.get("score")
                    else:
                        cvss = getattr(vv, "cvss", None) or getattr(vv, "score", None)
                    if cvss is not None and float(cvss) >= 7.0:
                        high_cvss += 1
                except Exception:
                    pass

            per_service.append({"port": port, "product": prod, "cves": sorted(set(svc_cves)), "cve_count": len(set(svc_cves)), "high_cvss": high_cvss})
    except Exception:
        per_service = []

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
        "per_service": per_service,
        "service_rows": service_rows,
        "top_vulns": top_vulns,
    }
