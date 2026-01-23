"""Minimal local-only CVE enricher.

This module intentionally avoids network calls. It only derives per-CVE
evidence from the provided ``technical_json`` (ports and embedded CVSS).
It provides flexible wrappers expected by other modules in the codebase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import re
import time

try:
    from shodan_report.clients.nvd_client import NvdClient
except Exception:  # pragma: no cover - defensive for minimal environments
    NvdClient = None

try:
    from shodan_report.clients.cisa_client import CisaClient
except Exception:  # pragma: no cover - defensive for minimal environments
    CisaClient = None


def _default_cache_path() -> Path:
    p = Path(".cache") / "shodan_report" / "cve_cache.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_cache(path: Optional[Path] = None) -> Dict[str, Any]:
    path = path or _default_cache_path()
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8") or "{}")
    except Exception:
        return {}
    return {}


def _save_cache(cache: Dict[str, Any], path: Optional[Path] = None) -> None:
    path = path or _default_cache_path()
    try:
        path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _get_cached_nvd(cache: Dict[str, Any], cve_id: str, ttl_seconds: int) -> Optional[Dict[str, Any]]:
    try:
        if ttl_seconds == 0:
            return None
        nvd = cache.get("nvd", {}) if isinstance(cache, dict) else {}
        entry = nvd.get(cve_id)
        if not isinstance(entry, dict):
            return None
        ts = entry.get("ts")
        if ts is None:
            return None
        if ttl_seconds > 0 and (time.time() - float(ts)) > ttl_seconds:
            return None
        data = entry.get("data")
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _set_cached_nvd(cache: Dict[str, Any], cve_id: str, data: Dict[str, Any]) -> None:
    try:
        if not isinstance(cache, dict):
            return
        nvd = cache.setdefault("nvd", {})
        if isinstance(nvd, dict):
            nvd[cve_id] = {"ts": time.time(), "data": data}
    except Exception:
        return


def _normalize_cves(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v]
    return [str(value)]


def _normalize_cpes(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v]
    return [str(value)]


def extract_service_from_cpe(cpe: str) -> Optional[str]:
    """Extract a conservative service label from a CPE string.

    Returns None if no confident product label can be derived.
    """
    if not cpe or not isinstance(cpe, str):
        return None

    # Accept both 2.3 and 2.2 formats: cpe:2.3:a:vendor:product:... or cpe:/a:vendor:product:...
    match = re.match(r"^cpe:(?:2\.3:)?[^:]+:([^:]*):([^:]*):", cpe)
    if not match:
        return None

    vendor = (match.group(1) or "").replace("_", " ").strip().lower()
    product = (match.group(2) or "").replace("_", " ").strip().lower()
    if not product or product in ("*", "-"):
        return None

    # Minimal, conservative mappings
    if "openssh" in product:
        return "OpenSSH"
    if "apache" in vendor and "http" in product:
        return "Apache HTTP Server"
    if "nginx" in product:
        return "Nginx"
    if "mysql" in product or "mariadb" in product:
        return "MySQL"
    if "postgres" in product:
        return "PostgreSQL"
    if "microsoft" in vendor and "iis" in product:
        return "IIS"
    if "ftp" in product:
        return "FTP"
    if "smtp" in product:
        return "SMTP"
    if "dns" in product or "bind" in product:
        return "DNS"

    # Fallback: title-case product, truncated
    return product.title()[:30]


def _extract_nvd_fields(nvd_json: Dict[str, Any]) -> Dict[str, Any]:
    """Extract minimal fields from a NVD-like JSON structure."""
    out: Dict[str, Any] = {
        "summary": None,
        "cvss": None,
        "service": None,
    }

    try:
        items = (
            nvd_json.get("result", {}).get("CVE_Items")
            or nvd_json.get("CVE_Items")
            or []
        )
        if not items:
            return out

        item = items[0]

        # Summary
        try:
            desc = item.get("cve", {}).get("description", {}).get("description_data", [])
            if desc and isinstance(desc, list):
                out["summary"] = desc[0].get("value")
        except Exception:
            pass

        # CVSS
        try:
            cvss = None
            impact = item.get("impact", {})
            v3 = impact.get("baseMetricV3", {})
            if v3:
                cvss = v3.get("cvssV3", {}).get("baseScore")
            if cvss is None:
                v2 = impact.get("baseMetricV2", {})
                cvss = v2.get("cvssV2", {}).get("baseScore")
            if cvss is not None:
                out["cvss"] = float(cvss)
        except Exception:
            pass

        # Service/product label (conservative)
        try:
            vendor_data = (
                item.get("cve", {})
                .get("affects", {})
                .get("vendor", {})
                .get("vendor_data", [])
            )
            if vendor_data:
                v0 = vendor_data[0]
                products = v0.get("product", {}).get("product_data", [])
                if products:
                    out["service"] = products[0].get("product_name") or v0.get("vendor_name")
        except Exception:
            pass

    except Exception:
        return out

    return out


def _find_first_cpe_in_nvd(nvd_json: Dict[str, Any]) -> Optional[str]:
    try:
        items = (
            nvd_json.get("result", {}).get("CVE_Items")
            or nvd_json.get("CVE_Items")
            or []
        )
        configs = []
        if items:
            item = items[0]
            # Older NVD v1 structure
            configs = item.get("configurations") or item.get("cve", {}).get("configurations") or []

        # If no configs found in CVE_Items, fall back to NVD v2 structure
        if not configs:
            vulns = nvd_json.get("vulnerabilities") or []
            v0 = vulns[0] if isinstance(vulns, list) and vulns else {}
            configs = v0.get("cve", {}).get("configurations") or v0.get("configurations") or []

        def _walk(obj: Any) -> Optional[str]:
            if isinstance(obj, dict):
                for k in ("cpe23Uri", "cpe23", "cpe", "cpe22Uri", "criteria"):
                    val = obj.get(k)
                    if isinstance(val, str) and val.startswith("cpe:"):
                        return val
                for v in obj.values():
                    found = _walk(v)
                    if found:
                        return found
            elif isinstance(obj, list):
                for v in obj:
                    found = _walk(v)
                    if found:
                        return found
            return None

        return _walk(configs)
    except Exception:
        return None


def build_cve_port_map(technical_json: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Build mapping: CVE ID -> {ports, max_cvss, cpes} from local snapshot."""
    mapping: Dict[str, Dict[str, Any]] = {}
    if not technical_json or not isinstance(technical_json, dict):
        return mapping

    services = technical_json.get("services") or technical_json.get("open_ports") or []
    for s in services:
        if isinstance(s, dict):
            port = s.get("port")
            sv_vulns = s.get("vulnerabilities") or s.get("vuls") or s.get("vulns") or s.get("cves") or []
            cpes = s.get("cpes") or s.get("cpe") or s.get("cpe23") or s.get("cpe23Uri") or []
        else:
            port = getattr(s, "port", None)
            sv_vulns = (
                getattr(s, "vulnerabilities", [])
                or getattr(s, "vuls", [])
                or getattr(s, "vulns", [])
                or getattr(s, "cves", [])
            )
            cpes = (
                getattr(s, "cpes", None)
                or getattr(s, "cpe", None)
                or getattr(s, "cpe23", None)
                or getattr(s, "cpe23Uri", None)
                or []
            )

        cpe_list = _normalize_cpes(cpes)

        for v in sv_vulns or []:
            try:
                if isinstance(v, str):
                    cid = v
                    cvss = None
                elif isinstance(v, dict):
                    cid = v.get("id") or v.get("cve") or v.get("name")
                    cvss = v.get("cvss") or v.get("cvss_score")
                else:
                    cid = getattr(v, "id", None) or getattr(v, "cve", None) or getattr(v, "name", None)
                    cvss = getattr(v, "cvss", None)
                if not cid:
                    continue
                cid = str(cid).strip()
                score = None
                try:
                    score = float(cvss) if cvss is not None else None
                except Exception:
                    score = None

                ent = mapping.setdefault(cid, {"ports": [], "max_cvss": None, "cpes": []})
                if port is not None and port not in ent["ports"]:
                    ent["ports"].append(port)
                if score is not None:
                    if ent["max_cvss"] is None or score > ent["max_cvss"]:
                        ent["max_cvss"] = score
                if cpe_list:
                    for cpe in cpe_list:
                        if cpe and cpe not in ent["cpes"]:
                            ent["cpes"].append(cpe)
            except Exception:
                continue

    return mapping


def enrich_cves_with_local(technical_json: Dict[str, Any], cve_ids: List[str]) -> List[Dict[str, Any]]:
    """Enrich CVEs with local snapshot data only (ports + CVSS)."""
    port_map = build_cve_port_map(technical_json or {})
    out: List[Dict[str, Any]] = []

    for cid in _normalize_cves(cve_ids):
        entry: Dict[str, Any] = {
            "id": cid,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cid}",
            "summary": None,
            "cvss": None,
            "ports": [],
            "service": None,
            "exploit_status": None,
            "sources": ["local_snapshot"],
        }
        pm = port_map.get(cid)
        if pm:
            entry["ports"] = pm.get("ports") or []
            entry["cvss"] = pm.get("max_cvss")

            cpes = pm.get("cpes") or []
            if cpes:
                label = None
                for cpe in cpes:
                    label = extract_service_from_cpe(cpe)
                    if label:
                        break
                if label:
                    entry["service_indicator"] = {
                        "matched_by": "cpe",
                        "confidence": "low",
                        "label": label,
                    }
                    entry["service_evidence"] = {"cpes": cpes[:3]}

        out.append(entry)

    return out


def enrich_cves_no_key(*args, **kwargs) -> List[Dict[str, Any]]:
    """Compatibility wrapper for older call signatures."""
    if len(args) == 1 and isinstance(args[0], (list, tuple, set, str)):
        cve_ids = _normalize_cves(args[0])
        technical_json = kwargs.get("technical_json") or {}
        return enrich_cves_with_local(technical_json or {}, cve_ids)
    if len(args) >= 2:
        technical_json = args[0] or {}
        cve_ids = _normalize_cves(args[1])
        return enrich_cves_with_local(technical_json or {}, cve_ids)
    technical_json = kwargs.get("technical_json") or {}
    cve_ids = _normalize_cves(kwargs.get("cve_ids") or kwargs.get("ids"))
    return enrich_cves_with_local(technical_json or {}, cve_ids)


def enrich_cves(*args, **kwargs) -> List[Dict[str, Any]]:
    """Flexible wrapper: support (technical_json, cve_ids) or (cve_ids, technical_json)."""
    technical_json: Optional[Dict[str, Any]] = None
    cve_ids: List[str] = []
    lookup_nvd = bool(kwargs.get("lookup_nvd"))
    show_progress = bool(kwargs.get("progress"))

    if len(args) >= 1:
        first = args[0]
        if isinstance(first, (list, tuple, set, str)):
            cve_ids = _normalize_cves(first)
            if len(args) >= 2 and isinstance(args[1], dict):
                technical_json = args[1]
        elif isinstance(first, dict):
            technical_json = first
            if len(args) >= 2 and isinstance(args[1], (list, tuple, set, str)):
                cve_ids = _normalize_cves(args[1])

    if technical_json is None:
        technical_json = kwargs.get("technical_json") or {}
    if not cve_ids:
        cve_ids = _normalize_cves(kwargs.get("cve_ids") or kwargs.get("ids"))

    enriched = enrich_cves_with_local(technical_json or {}, cve_ids)

    if not lookup_nvd:
        return enriched

    # Optional NVD + CISA enrichment for CVSS and exploit status
    cache_ttl = int(kwargs.get("cache_ttl", 60 * 60 * 24 * 7))  # 7 days
    cache_path = kwargs.get("cache_path")
    cache = _load_cache(cache_path) if lookup_nvd else {}
    nvd_client = kwargs.get("nvd")
    if nvd_client is None and NvdClient is not None:
        try:
            nvd_client = NvdClient()
        except Exception:
            nvd_client = None

    cisa_client = kwargs.get("cisa")
    if cisa_client is None and CisaClient is not None:
        try:
            cisa_client = CisaClient()
        except Exception:
            cisa_client = None

    kev_set = None
    try:
        if cisa_client is not None:
            kev_set = cisa_client.fetch_kev_set()
    except Exception:
        kev_set = None

    total = len(enriched)
    for idx, entry in enumerate(enriched, start=1):
        cid = entry.get("id")
        # Exploit status from CISA KEV
        try:
            if kev_set is not None and cid in kev_set:
                entry["exploit_status"] = "public"
                entry.setdefault("sources", []).append("cisa_kev")
        except Exception:
            pass

        # NVD fields
        if nvd_client is None or not cid:
            continue
        try:
            nvd_json = _get_cached_nvd(cache, cid, cache_ttl)
            if nvd_json is None:
                if show_progress:
                    print(f"[nvd] {idx}/{total} fetch {cid}")
                nvd_json = nvd_client.fetch_cve_json(cid)
                if isinstance(nvd_json, dict):
                    _set_cached_nvd(cache, cid, nvd_json)
            else:
                if show_progress:
                    print(f"[nvd] {idx}/{total} cache {cid}")
            nvd_fields = _extract_nvd_fields(nvd_json or {})

            if entry.get("summary") in (None, "") and nvd_fields.get("summary"):
                entry["summary"] = nvd_fields.get("summary")

            if entry.get("cvss") is None and nvd_fields.get("cvss") is not None:
                entry["cvss"] = nvd_fields.get("cvss")

            nvd_service = nvd_fields.get("service")
            if not nvd_service:
                cpe = _find_first_cpe_in_nvd(nvd_json or {})
                nvd_service = extract_service_from_cpe(cpe) if cpe else None

            if not entry.get("service") and nvd_service:
                entry["service"] = nvd_service
                entry["service_indicator"] = {
                    "matched_by": "nvd_cpe",
                    "confidence": "low",
                    "label": nvd_service,
                }
                if entry.get("summary") in (None, ""):
                    entry["summary"] = f"nicht bestätigt ({nvd_service}, OSINT-Indiz)"

            if nvd_fields.get("summary") or nvd_fields.get("cvss") or nvd_fields.get("service"):
                entry.setdefault("sources", []).append("nvd")
        except Exception:
            continue

    if lookup_nvd:
        _save_cache(cache, cache_path)

    return enriched

