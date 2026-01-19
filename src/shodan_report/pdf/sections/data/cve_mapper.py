from typing import Any, Dict, List


def normalize_cve_id(item: Any) -> str:
    """Normalize various CVE representations to a canonical CVE id string."""
    try:
        if item is None:
            return ""
        if isinstance(item, str):
            return item.strip()
        if isinstance(item, dict):
            return str(item.get("id") or item.get("cve") or item.get("name") or "").strip()
        cid = getattr(item, "id", None) or getattr(item, "cve", None) or getattr(item, "name", None)
        if cid:
            return str(cid).strip()
        return str(item).strip()
    except Exception:
        return str(item)


def assign_cves_to_services(technical_json: Any, unique_cves: List[str]) -> Dict[str, Any]:
    """Assign CVE ids to services based on per-service vulnerability lists.

    Returns dict {"per_service": [{"port":..., "cves": [...]}, ...], "unassigned": [...]}
    """
    per_service = []
    unassigned = []

    # Build set for fast lookup
    unique_set = set([c for c in (unique_cves or []) if c])

    # iterate services
    services = []
    if isinstance(technical_json, dict):
        services = technical_json.get("open_ports") or technical_json.get("services") or []
    else:
        services = getattr(technical_json, "open_ports", None) or getattr(technical_json, "services", []) or []

    assigned = set()
    for s in services:
        try:
            if isinstance(s, dict):
                port = s.get("port")
                sv_vulns = s.get("vulnerabilities") or s.get("vulns") or s.get("cves") or []
            else:
                port = getattr(s, "port", None)
                sv_vulns = getattr(s, "vulnerabilities", []) or getattr(s, "vulns", []) or getattr(s, "cves", [])

            svc_cves = []
            for vv in sv_vulns:
                cid = normalize_cve_id(vv)
                if cid and cid in unique_set:
                    svc_cves.append(cid)
                    assigned.add(cid)

            svc_cves = sorted(set(svc_cves))
            per_service.append({"port": port, "cves": svc_cves})
        except Exception:
            continue

    # any remaining unique CVEs are unassigned
    for c in sorted(unique_set):
        if c not in assigned:
            unassigned.append(c)

    return {"per_service": per_service, "unassigned": unassigned}
from typing import Any, Dict, List


def _normalize_cve(entry: Any) -> str:
    try:
        if entry is None:
            return ""
        if isinstance(entry, str):
            return entry.strip()
        if isinstance(entry, dict):
            return str(entry.get("id") or entry.get("cve") or entry.get("name") or "").strip()
        cid = getattr(entry, "id", None) or getattr(entry, "cve", None) or getattr(entry, "name", None)
        if cid:
            return str(cid).strip()
        return str(entry).strip()
    except Exception:
        return str(entry)


def assign_cves_to_services(technical_json: Dict[str, Any], unique_cves: List[str]) -> Dict[str, Any]:
    """Assign CVE ids to services using available per-service vulnerability lists.

    Heuristics:
    - If a service has its own `vulnerabilities`/`vulns`/`cves` list, normalize and assign those.
    - Remaining CVEs are returned as `unassigned` for later enrichment (NVD matching).

    Returns dict with keys `per_service` (list of {port, product, cves}) and `unassigned` (list).
    """
    services = []
    if isinstance(technical_json, dict):
        services = technical_json.get("open_ports") or technical_json.get("services") or []
    else:
        services = getattr(technical_json, "open_ports", None) or getattr(technical_json, "services", [])

    assigned = []
    assigned_ids = set()

    per_service = []
    for s in services:
        if isinstance(s, dict):
            port = s.get("port")
            prod = s.get("product") or (s.get("service") or {}).get("product") if isinstance(s.get("service"), dict) else s.get("product")
            sv_vulns = s.get("vulnerabilities") or s.get("vulns") or s.get("cves") or []
        else:
            port = getattr(s, "port", None)
            prod = getattr(s, "product", None)
            sv_vulns = getattr(s, "vulnerabilities", []) or getattr(s, "vulns", []) or getattr(s, "cves", [])

        normalized = []
        for v in sv_vulns:
            cid = _normalize_cve(v)
            if cid:
                normalized.append(cid)
                assigned_ids.add(cid)

        per_service.append({"port": port, "product": prod, "cves": sorted(set(normalized))})

    # Unassigned = unique_cves - assigned_ids
    unassigned = [c for c in unique_cves if c not in assigned_ids]

    return {"per_service": per_service, "unassigned": unassigned}
