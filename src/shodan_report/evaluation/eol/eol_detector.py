"""EOL detector — pure matching engine. No scoring, no side effects."""

from datetime import date
from typing import Any, Dict, List, Optional

from .eol_lookup import EOL_DB, NEAR_EOL_DAYS

_UNKNOWN_RESULT: Dict[str, Any] = {
    "product_id": None,
    "display_name": None,
    "eol_status": "unknown",
    "eol_date": None,
    "confidence": "low",
    "note": None,
}


def _normalize(s: str) -> str:
    return str(s).lower().strip() if s else ""


def _version_matches(entry_prefix: str, version: str) -> bool:
    """True if the given version matches the entry's prefix (dot-bounded).

    Also handles letter-suffix releases used by OpenSSL (e.g. "1.1.1t" → prefix "1.1.1").
    """
    if not entry_prefix:
        return True  # empty prefix matches any version
    v = _normalize(version)
    prefix = _normalize(entry_prefix)
    if v == prefix or v.startswith(prefix + "."):
        return True
    # Allow letter-suffix variants (OpenSSL style: "1.1.1t" matches "1.1.1")
    if v.startswith(prefix) and len(v) > len(prefix) and v[len(prefix)].isalpha():
        return True
    return False


def _product_matches(entry: Dict[str, Any], product: str, version: str) -> bool:
    """True if any shodan_products pattern is a substring of product OR version."""
    product_low = _normalize(product)
    version_low = _normalize(version)
    for pat in entry.get("shodan_products") or []:
        pat_low = _normalize(pat)
        if pat_low in product_low or pat_low in version_low:
            return True
    return False


def _determine_status(entry: Dict[str, Any], today: date):
    """Return (eol_status, eol_date_iso) for the given entry and date."""
    support_end = entry.get("support_end")
    if support_end is None:
        return "unknown", None
    eol_date_iso = support_end.isoformat()
    if today >= support_end:
        return "eol", eol_date_iso
    days_left = (support_end - today).days
    if days_left <= NEAR_EOL_DAYS:
        return "near_eol", eol_date_iso
    return "supported", eol_date_iso


def detect_eol(
    product: str,
    version: str,
    today: Optional[date] = None,
) -> Dict[str, Any]:
    """Match one (product, version) pair against the EOL database.

    Returns a dict with keys:
      product_id, display_name, eol_status, eol_date, confidence, note
    """
    if today is None:
        today = date.today()

    if not product:
        return dict(_UNKNOWN_RESULT)

    candidates = []
    for entry in EOL_DB:
        if not _product_matches(entry, product, version):
            continue
        prefix = entry.get("version_prefix", "")
        ver_match = _version_matches(prefix, version) if version else (not prefix)
        if not ver_match:
            continue
        # Confidence: high when a non-empty version prefix matched the actual version
        if prefix and version:
            confidence = "high"
        elif version:
            confidence = "medium"
        else:
            confidence = "low"
        candidates.append((entry, confidence))

    if not candidates:
        return dict(_UNKNOWN_RESULT)

    # Prefer more specific entries (non-empty prefix) and higher confidence
    _conf_rank = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(
        key=lambda x: (0 if x[0].get("version_prefix") else 1, _conf_rank[x[1]])
    )
    entry, confidence = candidates[0]

    status, eol_date = _determine_status(entry, today)
    return {
        "product_id": entry["product_id"],
        "display_name": entry["display_name"],
        "eol_status": status,
        "eol_date": eol_date,
        "confidence": confidence,
        # "official": unambiguous EOL; "mainstream_end": extended support may still apply
        "support_model": entry.get("support_model", "official"),
        "note": entry.get("note"),
    }


def scan_services_for_eol(
    services: List[Dict[str, Any]],
    today: Optional[date] = None,
) -> List[Dict[str, Any]]:
    """Scan a list of Shodan service dicts and return EOL/near-EOL findings.

    Only services with eol_status in {eol, near_eol} are returned.
    Findings are deduplicated by product_id — one finding per product.
    Each finding also includes the 'port' field from the source service.
    """
    if today is None:
        today = date.today()

    findings: List[Dict[str, Any]] = []
    seen: set = set()

    for svc in services or []:
        if not isinstance(svc, dict):
            continue
        product = svc.get("product") or ""
        version = svc.get("version") or ""
        result = detect_eol(product, version, today)
        if result["eol_status"] not in ("eol", "near_eol"):
            continue
        pid = result["product_id"]
        if pid in seen:
            continue
        seen.add(pid)
        findings.append({**result, "port": svc.get("port")})

    return findings
