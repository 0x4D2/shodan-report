from typing import Any, Dict, List, Optional

# DB ports considered higher risk when publicly reachable
DB_PORTS = {3306, 1433, 1521}

try:
    from .cve_enricher import build_cve_port_map
except Exception:
    build_cve_port_map = None

try:
    from .cve_mapper import normalize_cve_id
except Exception:
    normalize_cve_id = lambda x: str(x) if x is not None else ""


def _iter_services(technical_json: Any):
    # Prefer rich `services` entries when available (they contain product/version/banner).
    if isinstance(technical_json, dict):
        sv = technical_json.get("services")
        if sv:
            return sv
        return technical_json.get("open_ports") or []
    # For object-like inputs, prefer `services` attribute if present
    services_attr = getattr(technical_json, "services", None)
    if services_attr:
        return services_attr
    return getattr(technical_json, "open_ports", [])


def _extract_tls_info(svc: Any) -> Dict[str, Optional[Any]]:
    if not svc:
        return {
            "protocols": [],
            "weak_ciphers": False,
            "cert_expiry": None,
            "ciphers": [],
            "cert_issuer": None,
            "cert_subject": None,
            "cert_self_signed": None,
            "cert_valid_from": None,
        }

    if isinstance(svc, dict):
        si = svc.get("ssl_info") or {}
    else:
        si = getattr(svc, "ssl_info", None) or {}

    protocols = si.get("protocols") or si.get("supported_protocols") or []
    weak = bool(si.get("has_weak_cipher") or si.get("weaknesses") or si.get("issues"))
    cert_expiry = None
    cert_subject = None
    cert_issuer = None
    cert_self_signed = None
    cert_valid_from = None
    # try common fields
    cert = si.get("cert") if isinstance(si, dict) else None
    if cert and isinstance(cert, dict):
        cert_expiry = cert.get("not_after") or cert.get("valid_to")
        cert_valid_from = cert.get("not_before") or cert.get("valid_from")
        cert_subject = cert.get("subject") or cert.get("subject_cn") or cert.get("subject_dn")
        cert_issuer = cert.get("issuer") or cert.get("issuer_cn") or cert.get("issuer_dn")
        cert_self_signed = cert.get("self_signed")
        if cert_self_signed is None and cert_subject and cert_issuer:
            cert_self_signed = str(cert_subject) == str(cert_issuer)
    cert_expiry = cert_expiry or si.get("cert_expiry") or svc.get("cert_expiry") if isinstance(svc, dict) else cert_expiry

    ciphers = []
    try:
        if isinstance(si, dict):
            cipher = si.get("cipher") or si.get("ciphers") or {}
            if isinstance(cipher, dict):
                name = cipher.get("name") or cipher.get("cipher")
                if name:
                    ciphers.append(str(name))
            elif isinstance(cipher, list):
                for c in cipher:
                    if isinstance(c, dict):
                        name = c.get("name") or c.get("cipher")
                        if name:
                            ciphers.append(str(name))
                    else:
                        ciphers.append(str(c))
    except Exception:
        ciphers = []

    return {
        "protocols": protocols or [],
        "weak_ciphers": weak,
        "cert_expiry": cert_expiry,
        "ciphers": ciphers,
        "cert_issuer": cert_issuer,
        "cert_subject": cert_subject,
        "cert_self_signed": cert_self_signed,
        "cert_valid_from": cert_valid_from,
    }


def _extract_ssh_info(svc: Any) -> Dict[str, Any]:
    if not svc:
        return {}
    ssh = {}
    if isinstance(svc, dict):
        ssh = svc.get("ssh_info") or svc.get("ssh") or {}
    else:
        ssh = getattr(svc, "ssh_info", None) or getattr(svc, "ssh", None) or {}

    if not isinstance(ssh, dict) or not ssh:
        return {}

    auth = ssh.get("auth") or ssh.get("authentication") or []
    cipher = ssh.get("cipher") or {}
    if not isinstance(cipher, dict):
        cipher = {}
    kex = cipher.get("kex") or ssh.get("kex") or []
    enc = cipher.get("enc") or cipher.get("encryption") or []
    mac = cipher.get("mac") or ssh.get("mac") or []
    # Normalize dict-shaped payloads from some scanners
    if isinstance(kex, dict):
        kex = kex.get("kex_algorithms") or kex.get("server_host_key_algorithms") or []
    if isinstance(enc, dict):
        enc = enc.get("encryption_algorithms") or enc.get("ciphers") or []
    if isinstance(mac, dict):
        mac = mac.get("mac_algorithms") or mac.get("macs") or []
    version = ssh.get("version") or ssh.get("software") or ssh.get("product")

    return {
        "auth": [str(a) for a in auth] if isinstance(auth, (list, tuple)) else [str(auth)],
        "kex": [str(k) for k in kex] if isinstance(kex, (list, tuple)) else [str(kex)],
        "ciphers": [str(c) for c in enc] if isinstance(enc, (list, tuple)) else [str(enc)],
        "macs": [str(m) for m in mac] if isinstance(mac, (list, tuple)) else [str(mac)],
        "version": str(version) if version else "",
    }


def _extract_http_indicators(banner_text: Any, extra_text: Any = None) -> Dict[str, Any]:
    try:
        text = " ".join([str(banner_text or ""), str(extra_text or "")])
        if not text.strip():
            return {}
        low = text.lower()
        hsts = "strict-transport-security" in low

        redirect_https = False
        if "location:" in low:
            import re as _re

            if _re.search(r"location:\s*https://", low):
                redirect_https = True
        if "http/1.1 301" in low or "http/1.1 302" in low:
            if "https" in low:
                redirect_https = True

        methods = []
        try:
            import re as _re

            m = _re.search(r"allow:\s*([A-Z,\s]+)", text, flags=_re.IGNORECASE)
            if m:
                methods = [m.strip() for m in m.group(1).split(",") if m.strip()]
        except Exception:
            methods = []

        indicators = {}
        if hsts:
            indicators["hsts"] = True
        if redirect_https:
            indicators["redirect_https"] = True
        if methods:
            indicators["methods"] = methods
        if "x-frame-options" in low:
            indicators["x_frame_options"] = True
        if "content-security-policy" in low:
            indicators["csp"] = True
        if "x-content-type-options" in low:
            indicators["x_content_type_options"] = True
        return indicators
    except Exception:
        return {}


def _clean_display_field_local(v: Any, max_len: int = 80) -> str:
    try:
        if v is None:
            return ""
        s = str(v).strip()
        s = s.replace("\n", " ").replace("\r", " ")
        import re as _re

        s = _re.sub(r"\s+", " ", s)
        # redact long base64-like sequences
        if _re.search(r"[A-Za-z0-9+/]{40,}=*", s):
            return "[SSH-Key entfernt]"
        # remove IPv4-mapped IPv6 tokens like '::ffff:1.2.3.4'
        s = _re.sub(r"::ffff:\d{1,3}(?:\.\d{1,3}){3}\s*", "", s)
        # remove leading numeric FTP/SMTP codes like '220 '
        s = _re.sub(r"^[0-9]{3}\s+", "", s)
        # compact FTP banners
        if "ftp" in s.lower():
            return "FTP"
        if len(s) > max_len:
            return s[: max_len - 3] + "..."
        return s
    except Exception:
        try:
            return str(v)
        except Exception:
            return ""


def _normalize_product_local(prod: Any) -> str:
    try:
        if not prod:
            return ""
        p = str(prod).strip()
        low = p.lower()
        if "ssh-2.0" in low or "openssh" in low or "mod_sftp" in low or low.strip() == "ssh":
            if "mod_sftp" in low:
                return "SSH (mod_sftp)"
            return "SSH"
        # fallback: clean
        return _clean_display_field_local(p, max_len=60)
    except Exception:
        return str(prod)


def _looks_like_hostname(text: str) -> bool:
    try:
        t = str(text).strip()
        if not t or len(t) < 3:
            return False
        if " " in t or "/" in t or "<" in t or ">" in t:
            return False
        # must contain a dot and end with a plausible TLD
        if "." not in t:
            return False
        return bool(__import__("re").search(r"\.[A-Za-z]{2,}$", t))
    except Exception:
        return False


def _is_garbage_token(text: str) -> bool:
    try:
        t = str(text).strip().lower()
        if not t:
            return True
        if t in {"-", "*", "ok", "+ok", "* ok", "http/1.1", "http/1.0", "http/2", "http/2.0"}:
            return True
        if "document.location" in t or "<script" in t or "error 400" in t or "trying" in t:
            return True
        if "<html" in t or "<head" in t or "<body" in t:
            return True
        return False
    except Exception:
        return False


def _infer_product_from_text(text: str, port: Optional[int]) -> str:
    try:
        t = str(text or "").lower()
        if not t:
            return ""
        if "dovecot" in t and port in {110, 143, 993, 995}:
            return "Dovecot"
        if "postfix" in t and port in {25, 587}:
            return "Postfix smtpd"
        if "apache" in t and port in {80, 443, 8080, 8081}:
            return "Apache httpd"
        if "nginx" in t and port in {80, 443, 8080, 8081}:
            return "nginx"
        if "openssh" in t or "ssh-2.0" in t:
            return "SSH"
        if "ftp" in t and port == 21:
            return "FTP"
        if port in {80, 443, 8080, 8081}:
            return "HTTP"
        return ""
    except Exception:
        return ""


def _infer_product_from_port(port: Optional[int]) -> str:
    try:
        p = int(port) if port is not None else None
    except Exception:
        return ""
    if p == 21:
        return "FTP"
    if p in {25, 587}:
        return "SMTP"
    if p in {110, 995}:
        return "POP3"
    if p in {143, 993}:
        return "IMAP"
    if p in {80, 8080, 8081}:
        return "HTTP"
    if p == 443:
        return "HTTPS"
    return ""


def prepare_technical_detail(technical_json: Dict[str, Any], evaluation: Any) -> Dict[str, Any]:
    """Prepare structured technical detail per service for rendering.

    Returns dict with keys:
      - services: list of {port, product, version, banner, risk, cves_count, high_cvss_count, tls}
      - meta: aggregated counts
    """
    services_out: List[Dict[str, Any]] = []

    critical_services = technical_json.get("critical_services", []) if isinstance(technical_json, dict) else getattr(technical_json, "critical_services", []) or []

    total_cves = 0
    total_high = 0

    # Build a CVE->port & max_cvss map from available local data
    port_map = build_cve_port_map(technical_json) if build_cve_port_map else {}

    for s in _iter_services(technical_json):
        if isinstance(s, dict):
            port = s.get("port")
            product = s.get("product") or s.get("service") or ""
            version = s.get("version") or ""
            extra_info = s.get("extra_info") or ""
            banner = s.get("banner") or extra_info or ""
            # normalize nested product/service dicts
            if isinstance(product, dict):
                product = product.get("product") or product.get("name") or product.get("service") or ""
            if isinstance(version, dict):
                version = version.get("version") or version.get("name") or ""
            if isinstance(banner, dict):
                banner = banner.get("banner") or banner.get("text") or ""
        else:
            port = getattr(s, "port", None)
            product = getattr(s, "product", "")
            version = getattr(s, "version", "")
            banner = getattr(s, "banner", "")
            extra_info = getattr(s, "extra_info", None)
            if isinstance(product, dict):
                product = product.get("product") or product.get("name") or ""
            if isinstance(version, dict):
                version = version.get("version") or version.get("name") or ""
            if isinstance(banner, dict):
                banner = banner.get("banner") or banner.get("text") or ""

        # CVE counts
        cves = []
        if isinstance(s, dict):
            cves.extend(s.get("vulnerabilities") or s.get("vulns") or s.get("cves") or [])
        else:
            cves.extend(getattr(s, "vulnerabilities", []) or [])

        # evaluation-level CVEs may be included per-service in evaluation mapping — skip deep linking for now
        cve_count = len(cves)
        high_count = 0
        top_vuln = None
        top_cvss = None

        for cv in cves:
            try:
                cid = normalize_cve_id(cv)
                # try per-entry cvss first
                cvss = None
                if isinstance(cv, dict):
                    cvss = cv.get("cvss") or cv.get("cvss_score")
                else:
                    cvss = getattr(cv, "cvss", None)

                # fallback to port_map if available
                if (cvss is None or cvss == "") and cid and port_map.get(cid):
                    cvss = port_map.get(cid, {}).get("max_cvss")

                score = None
                try:
                    score = float(cvss) if cvss is not None else None
                except Exception:
                    score = None

                if score is not None and score >= 7.0:
                    high_count += 1

                if score is not None and (top_cvss is None or score > top_cvss):
                    top_cvss = score
                    top_vuln = {"id": cid, "cvss": score}
            except Exception:
                continue

        total_cves += cve_count
        total_high += high_count

        tls = _extract_tls_info(s)
        ssh_info = _extract_ssh_info(s)
        http_info = _extract_http_indicators(banner, extra_info if isinstance(s, dict) else None)

        # If version missing, try multiple heuristics to extract it:
        # 1) nested dicts under common keys ('service','product','extra','meta')
        # 2) product-specific pattern in banner (e.g. "MySQL 8.0.33")
        # 3) generic numeric version pattern in banner
        if not version and isinstance(s, dict):
            for key in ("service", "product", "extra", "meta"):
                try:
                    nested = s.get(key)
                    if isinstance(nested, dict):
                        version = version or nested.get("version") or nested.get("ver") or nested.get("name")
                        # also attempt to extract product from nested if missing
                        if not product:
                            product = product or nested.get("product") or nested.get("name")
                    elif isinstance(nested, str) and not product:
                        product = nested
                    if version:
                        break
                except Exception:
                    continue

        # Avoid inferring 'version' from banner for DNS services (port 53)
        if port == 53 or (isinstance(product, str) and "dns" in product.lower()):
            # keep version empty and preserve banner/extrainfo for details
            version = version
        elif not version and isinstance(banner, str) and banner:
            try:
                re = __import__("re")
                # If we know the product name, try a product-specific pattern first
                if product:
                    try:
                        prod_escaped = re.escape(str(product))
                        m = re.search(rf"{prod_escaped}[^\d\n]{{0,30}}(\d+\.\d+(?:\.\d+)*)", banner, flags=re.IGNORECASE)
                        if m:
                            version = m.group(1)
                    except Exception:
                        pass

                # Fallback: any numeric-looking version in the banner
                if not version:
                    m = re.search(r"(\d+\.\d+(?:\.\d+)*)", banner)
                    if m:
                        version = m.group(1)
            except Exception:
                pass

        if not version and isinstance(banner, str) and banner:
            if banner.strip().startswith("1.1") or "HTTP/1.1" in banner:
                version = "1.1"

        # Preserve original banner for extraction and sidecar forensic use
        banner_orig = banner

        # Extract Server: header from original banner or raw_version_text and remove it from banner
        raw_version_text = version
        server = ""
        try:
            import re as _re
            # look for a Server: header anywhere and remove the whole header line(s)
            if isinstance(banner_orig, str) and banner_orig:
                msv = _re.search(r"Server:\s*([^\r\n]+)", banner_orig, flags=_re.IGNORECASE)
                if msv:
                    # sanitize Server: value to a short, single token (avoid header dumps)
                    serv_raw = msv.group(1)
                    try:
                        # cut off before other header-like tokens (e.g. 'X-Frame-Options:', 'Date:', 'Content-Type:')
                        serv_short = _re.split(r"\s+(?=[A-Z][A-Za-z-]+:)", serv_raw)[0]
                    except Exception:
                        serv_short = serv_raw
                    # further cut on semicolons/commas or a trailing HTTP token
                    serv_short = serv_short.split(";")[0].split(",")[0]
                    serv_short = serv_short.split("HTTP")[0].strip()
                    server = " ".join(serv_short.split())
                    if len(server) > 60:
                        server = server[:57] + "..."
                    # remove Server: ... occurrences from the printable banner
                    try:
                        banner = _re.sub(r'(?im)Server:\s*[^\r\n]+', "", banner_orig)
                    except Exception:
                        # best-effort fallback
                        try:
                            banner = banner_orig.replace(msv.group(0), "")
                        except Exception:
                            banner = banner_orig
                else:
                    banner = banner_orig
            else:
                banner = banner_orig
        except Exception:
            banner = banner_orig

        # Sanitize version/value to remove long header dumps and newlines
        def _sanitize_version(ver, banner_text, prod, port_num):
            try:
                if ver is None:
                    return ""
                s = str(ver)
                # collapse whitespace and remove stray newlines
                s = " ".join(s.split())
                # If this looks like an HTTP header dump or is very long, try to extract short tokens
                lower = s.lower()
                header_indicators = ("content-type:", "content-length:", "date:", "server:", "http/", "content-security-policy", "x-frame-options")
                if len(s) > 100 or any(h in lower for h in header_indicators):
                    try:
                        import re as _re

                        # Prefer extracting short tokens (HTTP/x.y) from either banner_text or
                        # the version string. Do not return full header dumps as 'version'.
                        target_texts = []
                        if isinstance(banner_text, str) and banner_text:
                            target_texts.append(banner_text)
                        if isinstance(s, str) and s:
                            target_texts.append(s)

                        # Check for Server: header first; if found prefer HTTP token or product
                        for txt in target_texts:
                            if not txt:
                                continue
                            m = _re.search(r"Server:\s*([^\r\n]+)", txt, flags=_re.IGNORECASE)
                            if m:
                                servv = " ".join(m.group(1).split())
                                m_http = _re.search(r"(HTTP/\d\.\d)", txt, flags=_re.IGNORECASE)
                                if m_http:
                                    return m_http.group(1)
                                return prod or (servv if len(servv) <= 80 else servv[:77] + "...")

                        # Fallback: look for HTTP/x.y token
                        for txt in target_texts:
                            if not txt:
                                continue
                            m3 = _re.search(r"(HTTP/\d\.\d)", txt, flags=_re.IGNORECASE)
                            if m3:
                                return m3.group(1)

                        # As a last resort, map a leading bare numeric '1.1' to HTTP/1.1
                        for txt in target_texts:
                            if not txt:
                                continue
                            m4 = _re.search(r"^\s*(\d\.\d)\b", txt)
                            if m4:
                                return f"HTTP/{m4.group(1)}"
                    except Exception:
                        pass
                    # fallback to product label if available
                    if prod:
                        return str(prod)
                    return ""

                # If the sanitized string is just a bare numeric like '1.1', map to 'HTTP/1.1'
                if _re.match(r"^\d\.\d$", s):
                    return f"HTTP/{s}"

                # truncate overly long but not header-like strings
                if len(s) > 80:
                    return s[:77] + "..."
                return s
            except Exception:
                try:
                    return str(ver)
                except Exception:
                    return ""
        version = _sanitize_version(version, banner, product, port)

        # If server wasn't found previously, try a final pass on raw texts
        try:
            if not server:
                import re as _re
                targets = []
                if isinstance(banner_orig, str) and banner_orig:
                    targets.append(banner_orig)
                if isinstance(raw_version_text, str) and raw_version_text:
                    targets.append(raw_version_text)
                for txt in targets:
                    if not txt:
                        continue
                    m = _re.search(r"Server:\s*([^\r\n]+)", txt, flags=_re.IGNORECASE)
                    if m:
                        serv_raw = m.group(1)
                        try:
                            serv_short = _re.split(r"\s+(?=[A-Z][A-Za-z-]+:)", serv_raw)[0]
                        except Exception:
                            serv_short = serv_raw
                        serv_short = serv_short.split(";")[0].split(",")[0]
                        serv_short = serv_short.split("HTTP")[0].strip()
                        server = " ".join(serv_short.split())
                        if len(server) > 60:
                            server = server[:57] + "..."
                        break
                    m2 = _re.search(r"(HTTP/\d\.\d)", txt, flags=_re.IGNORECASE)
                    if m2:
                        server = m2.group(1)
                        break
        except Exception:
            server = server or ""

        # Cleanup noisy product/version/server fields from banner-like content
        try:
            prod_raw = str(product or "").strip()
            ver_raw = str(version or "").strip()
            banner_text = banner_orig if isinstance(banner_orig, str) else (str(banner or ""))

            if _is_garbage_token(prod_raw):
                if ver_raw and not _is_garbage_token(ver_raw):
                    # keep HTTP version tokens as version, not product
                    if ver_raw in {"1.0", "1.1", "2.0"} or "HTTP/1.1" in banner_text or "HTTP/2" in banner_text:
                        product = product or _infer_product_from_port(port) or "HTTP"
                        prod_raw = str(product)
                    else:
                        product, version = ver_raw, ""
                        prod_raw, ver_raw = str(product), ""
                else:
                    product = ""
                    prod_raw = ""

            if not prod_raw:
                inferred = _infer_product_from_text(ver_raw, port) or _infer_product_from_text(banner_text, port)
                if inferred:
                    product = inferred
                    prod_raw = inferred

            if not prod_raw:
                inferred_port = _infer_product_from_port(port)
                if inferred_port:
                    product = inferred_port
                    prod_raw = inferred_port

            if prod_raw and "postfix" in prod_raw.lower():
                if ver_raw and _looks_like_hostname(ver_raw):
                    server = ver_raw
                    version = ""
                    ver_raw = ""
                elif not server and banner_text:
                    import re as _re

                    mh = _re.search(r"\b([A-Za-z0-9._-]+\.[A-Za-z]{2,})\b", banner_text)
                    if mh:
                        server = mh.group(1)

            if prod_raw and "dovecot" in prod_raw.lower() and _is_garbage_token(ver_raw):
                version = ""
                ver_raw = ""

            if prod_raw and ver_raw and prod_raw.lower() == ver_raw.lower():
                version = ""
                ver_raw = ""

            if ver_raw and _is_garbage_token(ver_raw):
                version = ""
        except Exception:
            pass

        # heuristic risk: high if any high CVE or marked critical, medium if tls issues or some CVEs, else low
        is_critical_flag = False
        try:
            if isinstance(s, dict):
                is_critical_flag = bool(s.get("critical") or s.get("_version_risk", 0) or s.get("version_risk", 0))
            else:
                is_critical_flag = bool(getattr(s, "critical", False) or getattr(s, "_version_risk", 0) or getattr(s, "version_risk", 0))
        except Exception:
            is_critical_flag = False

        # dynamic rules: DB ports without restrictions are considered higher risk
        if ((top_cvss is not None and top_cvss >= 7.0) or is_critical_flag):
            risk = "hoch"
        elif (port in DB_PORTS):
            # database ports on public interfaces are escalated to high
            risk = "hoch"
        elif tls.get("weak_ciphers") or cve_count > 0:
            risk = "mittel"
        else:
            risk = "niedrig"

        # Apply conservative sanitization for output fields
        prod_out = _normalize_product_local(product)
        ver_out = _clean_display_field_local(version, max_len=80)
        banner_out = _clean_display_field_local(banner, max_len=200)

        services_out.append(
            {
                "port": port,
                "product": prod_out,
                "version": ver_out,
                "server": server,
                "banner": banner_out,
                "risk": risk,
                "cve_count": cve_count,
                "high_cvss": high_count,
                "tls": tls,
                "ssh": ssh_info,
                "http": http_info,
                "top_vuln": top_vuln,
            }
        )

    # Deduplicate services by (port, product, server, banner-snippet) to avoid repeated DNS rows
    deduped = []
    seen = set()
    for svc in services_out:
        try:
            port_k = svc.get("port")
            prod_k = (svc.get("product") or "").strip().lower()
            serv_k = (svc.get("server") or "").strip().lower()
            banner_snip = (svc.get("banner") or "")[:120].strip()
            key = (port_k, prod_k, serv_k, banner_snip)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(svc)
        except Exception:
            deduped.append(svc)

    return {
        "services": deduped,
        "meta": {"total_services": len(deduped), "total_cves": total_cves, "total_high_cvss": total_high},
        # CVE assignment helper output: per-service explicit CVE lists and unassigned CVEs
        "cve_assignments": _build_cve_assignments(technical_json, deduped),
    }



def _build_cve_assignments(technical_json: Dict[str, Any], services_out: List[Dict[str, Any]]) -> Dict[str, Any]:
    try:
        from .cve_mapper import assign_cves_to_services
    except Exception:
        return {"per_service": [], "unassigned": []}

    # Build a canonical unique_cves list from technical_json top-level vulns
    unique = []
    if isinstance(technical_json, dict):
        unique = technical_json.get("vulns") or technical_json.get("vulnerabilities") or []
    # normalize to strings
    try:
        from .cve_mapper import normalize_cve_id as _md_extract  # type: ignore
    except Exception:
        def _md_extract(x):
            try:
                return str(x)
            except Exception:
                return ""

    normalized = []
    for v in unique:
        try:
            normalized.append(_md_extract(v))
        except Exception:
            try:
                normalized.append(str(v))
            except Exception:
                continue

    result = assign_cves_to_services(technical_json, normalized)
    return result
