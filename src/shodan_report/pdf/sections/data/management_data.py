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
        # Deduplicate critical points while preserving order. Prefer sanitized
        # canonical forms to collapse near-duplicates (e.g. same product/version).
        try:
            from shodan_report.pdf.helpers.management_helpers import _sanitize_critical_point
        except Exception:
            _sanitize_critical_point = None

        seen_cp = set()
        deduped_cp = []
        # helper regex to canonicalize product+version pairs
        pv_re = None
        try:
            import re

            pv_re = re.compile(r"\b(mysql|nginx|apache|openssh|clickhouse|postfix|ssh)[^\d\n]{0,30}?(\d+\.\d+(?:\.\d+)*)\b", flags=re.IGNORECASE)
        except Exception:
            pv_re = None

        for cp in (critical_points or []):
            try:
                raw = str(cp).strip()
            except Exception:
                raw = cp
            if not raw:
                continue
            # create a human-friendly sanitized form for display
            if _sanitize_critical_point:
                try:
                    display_text = _sanitize_critical_point(raw, max_length=200)
                except Exception:
                    display_text = raw
            else:
                display_text = raw

            # canonical uniqueness key: product + version if found, else sanitized lowercased
            uniq = None
            try:
                if pv_re:
                    m = pv_re.search(display_text)
                    if not m:
                        m = pv_re.search(raw)
                    if m:
                        prod = m.group(1).lower()
                        ver = m.group(2)
                        uniq = f"{prod} {ver}"
            except Exception:
                uniq = None

            if not uniq:
                uniq = str(display_text).strip().lower()

            if not uniq:
                continue

            if uniq not in seen_cp:
                seen_cp.add(uniq)
                deduped_cp.append(display_text)

        critical_points = deduped_cp
        critical_points_count = len(critical_points)
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

    if isinstance(technical_json, dict):
        # Accept both legacy `open_ports` and richer `services` keys as the source
        open_ports = technical_json.get("open_ports") or technical_json.get("services") or []
        top_vulns = (
            technical_json.get("vulns")
            or technical_json.get("vulnerabilities")
            or technical_json.get("vulns_list")
            or []
        )
    else:
        open_ports = getattr(technical_json, "open_ports", None) or getattr(technical_json, "services", []) or []
        top_vulns = (
            getattr(technical_json, "vulns", [])
            or getattr(technical_json, "vulnerabilities", [])
            or getattr(technical_json, "vulns_list", [])
            or []
        )

    total_ports = len(open_ports) if open_ports else 0

    eval_cves = []
    if isinstance(evaluation, dict):
        eval_cves = evaluation.get("cves", []) or []
    else:
        eval_cves = getattr(evaluation, "cves", []) or []

    def _extract_cve_id(item: Any) -> str:
        # normalize different CVE representations to a canonical string id
        try:
            if item is None:
                return ""
            if isinstance(item, str):
                return item.strip()
            if isinstance(item, dict):
                return str(item.get("id") or item.get("cve") or item.get("name") or "").strip()
            # objects with attributes
            cid = getattr(item, "id", None) or getattr(item, "cve", None) or getattr(item, "name", None)
            if cid:
                return str(cid).strip()
            return str(item).strip()
        except Exception:
            return str(item)

    unique_cves = set()
    for v in list(top_vulns) + list(eval_cves):
        cid = _extract_cve_id(v)
        if cid:
            unique_cves.add(cid)

    # include per-service vulnerabilities if present
    try:
        for svc in open_ports or []:
            if isinstance(svc, dict):
                sv_vulns = svc.get("vulnerabilities") or svc.get("_cves") or svc.get("vulns") or []
            else:
                sv_vulns = getattr(svc, "vulnerabilities", []) or getattr(svc, "_cves", []) or getattr(svc, "vulns", []) or []
            for vv in sv_vulns:
                cid = _extract_cve_id(vv)
                if cid:
                    unique_cves.add(cid)
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
