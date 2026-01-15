import re
from typing import Any, Dict, Optional


_BANNER_PATTERNS = [
    (re.compile(r"(?i)(nginx)(?:/|\s)?([0-9]+(?:\.[0-9]+)*)"), "nginx"),
    (re.compile(r"(?i)(apache)(?:/|\s)?([0-9.]+)?"), "apache"),
    (re.compile(r"(?i)(openssh)(?:[_\-]|\s)?([0-9.]+)?"), "OpenSSH"),
    (re.compile(r"(?i)(mysql|mariadb)(?:/|\s)?([0-9.]+)?"), "MySQL"),
    (re.compile(r"(?i)(clickhouse)(?:/|\s)?([0-9.]+)?"), "ClickHouse"),
    (re.compile(r"(?i)(tomcat)(?:/|\s)?([0-9.]+)?"), "Tomcat"),
    (re.compile(r"(?i)(jetty)(?:/|\s)?([0-9.]+)?"), "Jetty"),
    (re.compile(r"(?i)(php)(?:/|\s)?([0-9.]+)?"), "PHP"),
    (re.compile(r"(?i)(openssl)(?:/|\s)?([0-9.]+)?"), "OpenSSL"),
    (re.compile(r"(?i)(postgresql|postgres)(?:/|\s)?([0-9.]+)?"), "PostgreSQL"),
    (re.compile(r"(?i)(microsoft-?iis)(?:/|\s)?([0-9.]+)?"), "IIS"),
]

# generic version matcher (numbers like 1.2 or 1.2.3)
_GENERIC_VER = re.compile(r"([0-9]+(?:\.[0-9]+){1,})")


def _norm_product(name: str) -> str:
    if not name:
        return ""
    name = name.strip()
    mapping = {"nginx": "NGINX", "apache": "Apache", "openssh": "OpenSSH", "mysql": "MySQL", "mariadb": "MySQL", "clickhouse": "ClickHouse", "tomcat": "Tomcat"}
    return mapping.get(name.lower(), name)


def extract_service_identity(service: Any) -> Dict[str, Optional[Any]]:
    """Extract canonical service identity from various shapes.

    Returns dict: {port, product, version, confidence}
    confidence: 'high'|'medium'|'low'
    """
    port = None
    product = None
    version = None
    confidence = "low"

    # dict-like explicit fields
    if isinstance(service, dict):
        port = service.get("port") or service.get("p")
        # service may contain nested 'service' dict
        svc = service.get("service") if isinstance(service.get("service"), dict) else None
        if svc:
            product = svc.get("product") or svc.get("name")
            version = svc.get("version") or svc.get("ver")

        # fallback to top-level keys
        if not product:
            product = service.get("product") or service.get("service")
            if isinstance(product, dict):
                product = product.get("product") or product.get("name")
        if not version:
            version = service.get("version") or service.get("ver") or service.get("banner_version")

        # if explicit product/version found -> high confidence
        if product:
            product = _norm_product(str(product))
            if version:
                confidence = "high"

        # banner heuristics
        banner = service.get("banner") or service.get("server") or service.get("product_info") or ""
    else:
        # service may be an int (port) or object-like
        try:
            port = getattr(service, "port", None)
        except Exception:
            port = None
        # attempt banner-like attributes
        banner = getattr(service, "banner", None) or getattr(service, "server", None) or str(service)

    banner = banner or ""

    # apply banner regexes if no high-confidence product
    if (not product) and banner:
        bstr = str(banner)
        for pat, name in _BANNER_PATTERNS:
            m = pat.search(bstr)
            if m:
                product = _norm_product(name)
                ver = None
                try:
                    ver = m.group(2)
                except Exception:
                    ver = None
                if ver:
                    version = ver
                    confidence = "medium"
                else:
                    # try generic version extract near product name
                    try:
                        # look for digits after the matched span
                        span_end = m.end()
                        tail = bstr[span_end: span_end + 40]
                        gm = _GENERIC_VER.search(tail)
                        if gm:
                            version = gm.group(1)
                            confidence = "medium"
                        else:
                            # try full string generic extract as last resort
                            gm2 = _GENERIC_VER.search(bstr)
                            if gm2:
                                version = gm2.group(1)
                                confidence = "low"
                    except Exception:
                        pass
                break

    # generic version extraction if product known but no explicit version
    if product and not version and banner:
        gm = _GENERIC_VER.search(str(banner))
        if gm:
            version = gm.group(1)
            # if product was inferred by port earlier, keep low confidence
            if confidence != "high":
                confidence = "medium"

    # Port-based fallback mapping for common services
    if not product and isinstance(port, int):
        port_map = {22: "OpenSSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 8123: "ClickHouse", 9000: "ClickHouse"}
        if port in port_map:
            product = port_map[port]
            confidence = "low"

    return {"port": port, "product": product, "version": version, "confidence": confidence}
