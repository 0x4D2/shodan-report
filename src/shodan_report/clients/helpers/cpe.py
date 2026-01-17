"""CPE helpers: extract and normalize product/vendor names from NVD CPE data."""
from typing import Dict, Any, List
import re
import html


def _normalize(name: str) -> str:
    if not name:
        return ''
    n = name.lower()
    n = re.sub(r'[^a-z0-9]+', ' ', n)
    return n.strip()


def determine_service_indicator_from_nvd(nvd_parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Return an indicator derived only from NVD parsed info.

    Args:
        nvd_parsed: dict from NVD JSON parser or HTML fallback. Expected keys
            may include `cpe_products` (list of product/vendor strings) or
            `cpe_uris` (list of full cpe:2.3 URIs).

    Returns a dict with the following keys (minimal, NVD‑only):
        - status: 'inferred' if any NVD CPEs present, else 'not_confirmed'
        - services_display: list of human readable product names (from CPEs)
        - matched_by: 'nvd_cpe'
        - confidence: 'low' when inferred, else None
        - evidence: list of raw CPE URIs or product strings

    This function performs NO relevance scoring or sidecar matching.
    """
    services: List[str] = []
    evidence: List[str] = []

    if not nvd_parsed:
        return {
            'status': 'not_confirmed',
            'services_display': [],
            'matched_by': None,
            'confidence': None,
            'evidence': [],
        }

    # Prefer explicit cpe_uris if present
    cpe_uris = nvd_parsed.get('cpe_uris') or []
    if cpe_uris:
        # sanitize and extract clean CPE tokens
        clean_uris: List[str] = []
        for raw in cpe_uris:
            # unescape HTML entities
            u = html.unescape(raw)
            # try to extract the first valid cpe:2.3:... token inside the string
            m = re.search(r'(cpe:2\.3:[^\s,\"\'>\]]+)', u, flags=re.IGNORECASE)
            token = m.group(1) if m else u
            token = token.strip().rstrip('.,;')
            # ignore obviously malformed tokens
            if 'cpe:2.3' in token.lower():
                clean_uris.append(token)

        if clean_uris:
            evidence.extend(clean_uris)
            # extract product tokens from URIs: cpe:2.3:a:vendor:product:version:...
            for uri in clean_uris:
                parts = uri.split(':')
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    # prefer product if meaningful, otherwise vendor
                    chosen = None
                    if product and product != '*':
                        chosen = product
                    elif vendor and vendor != '*':
                        chosen = vendor
                    if chosen:
                        # strip trailing numeric version tokens if they crept in
                        chosen = re.sub(r'^[0-9\._-]+|[0-9\._-]+$', '', chosen)
                        # final cleanup: remove non-alphanumeric prefix/suffix
                        chosen = re.sub(r'[^A-Za-z0-9_\-]+', '', chosen)
                        if chosen:
                            services.append(chosen)

    # fallback to cpe_products (normalized strings)
    if not evidence:
        for p in (nvd_parsed.get('cpe_products') or []):
            if p:
                evidence.append(p)
                services.append(p)

    # normalize display names (deduplicate preserving order)
    seen = set()
    disp = []
    for s in services:
        if not s:
            continue
        key = _normalize(s)
        if key and key not in seen:
            seen.add(key)
            disp.append(s)

    if disp:
        return {
            'status': 'inferred',
            'services_display': disp,
            'matched_by': 'nvd_cpe',
            'confidence': 'low',
            'evidence': evidence,
        }

    return {
        'status': 'not_confirmed',
        'services_display': [],
        'matched_by': None,
        'confidence': None,
        'evidence': [],
    }
