from typing import Any, Dict, List

try:
    from ..data.management_data import prepare_management_data
except Exception:
    prepare_management_data = None

try:
    from .cve_enricher import enrich_cves
except Exception:
    enrich_cves = None


def _iter_services(technical_json: Any):
    if isinstance(technical_json, dict):
        return technical_json.get("open_ports") or technical_json.get("services") or []
    return getattr(technical_json, "open_ports", None) or getattr(technical_json, "services", [])


def _extract_cves_from(obj):
    if not obj:
        return []
    if isinstance(obj, dict):
        return obj.get("vulnerabilities") or obj.get("vulns") or obj.get("cves") or []
    return getattr(obj, "vulnerabilities", None) or getattr(obj, "vulns", None) or getattr(obj, "cves", [])


def prepare_recommendations_data(technical_json: Dict[str, Any], evaluation: Any, business_risk: str) -> Dict[str, Any]:
    """Prepare prioritized recommendation buckets from snapshot + evaluation.

    Heuristics used:
    - Priority 1: critical CVEs (cvss>=7) or TLS weaknesses
    - Priority 2: management ports reachable (SSH/RDP/DB), missing certs on 443, DNS port 53
    - Priority 3: hygiene / optional items
    """
    priority1: List[str] = []
    priority2: List[str] = []
    priority3: List[str] = []

    # collect CVEs
    cves = []
    # top-level vuln lists
    if isinstance(technical_json, dict):
        cves.extend(technical_json.get("vulnerabilities") or technical_json.get("vulns") or [])
    else:
        cves.extend(getattr(technical_json, "vulnerabilities", []) or [])

    # evaluation CVEs
    if isinstance(evaluation, dict):
        cves.extend(evaluation.get("cves") or [])
    else:
        cves.extend(getattr(evaluation, "cves", []) or [])

    # per-service CVEs
    for s in _iter_services(technical_json):
        for cv in _extract_cves_from(s) or []:
            cves.append(cv)

    # count critical CVEs by cvss if available
    critical_count = 0
    for cv in cves:
        try:
            if isinstance(cv, dict):
                cvss = cv.get("cvss", 0) or 0
            else:
                cvss = getattr(cv, "cvss", 0) or 0
            if float(cvss) >= 7.0:
                critical_count += 1
        except Exception:
            continue

    # Also consider any pre-enriched CVE lists that may be present in the
    # generated `.mdata.json` (e.g. `cve_enriched` / `cve_enriched_sample`).
    try:
        enriched_candidates = []
        if isinstance(technical_json, dict):
            enriched_candidates = technical_json.get("cve_enriched") or technical_json.get("cve_enriched_sample") or technical_json.get("cve_enriched_list") or []
        if not enriched_candidates and isinstance(evaluation, dict):
            enriched_candidates = evaluation.get("cve_enriched") or evaluation.get("cve_enriched_sample") or []
        for ent in (enriched_candidates or []):
            try:
                if isinstance(ent, dict):
                    cvss = ent.get("cvss", None)
                else:
                    cvss = getattr(ent, "cvss", None)
                if cvss is None:
                    continue
                if float(cvss) >= 7.0:
                    critical_count += 1
            except Exception:
                continue
    except Exception:
        pass

    if critical_count:
        # initial detection (cvss >= 7)
        priority1.append(f"Kritische CVE(s) mit CVSS ≥7 identifiziert: {critical_count}")

    # Additionally, include CVEs discovered via management data / unique_cves
    try:
        management_cves = []
        if prepare_management_data:
            mdata = prepare_management_data(technical_json or {}, evaluation or {})
            management_cves = mdata.get("unique_cves", []) or []
        # Fallback: if evaluation contains enriched CVE objects, extract ids
        if not management_cves and isinstance(evaluation, dict):
            # try common fallback field names
            management_cves = evaluation.get("unique_cves") or evaluation.get("cve_ids") or []
        management_cves = [str(x).strip() for x in (management_cves or []) if x]

        if management_cves:
            # Enrich locally to get cvss values where possible (no NVD lookup)
            enriched = []
            if enrich_cves:
                try:
                    enriched = enrich_cves(management_cves, technical_json or {}, lookup_nvd=False)
                except Exception:
                    enriched = []

            # Count high (7<=cvss<9) and critical (cvss>=9)
            seen_ids = set()
            high_count = 0
            critical_count_9 = 0
            for ent in (enriched or []):
                try:
                    cid = (ent.get("id") or ent.get("cve") or ent.get("name")) if isinstance(ent, dict) else None
                    if not cid:
                        continue
                    cid = str(cid).strip()
                    if cid in seen_ids:
                        continue
                    seen_ids.add(cid)
                    cvss = ent.get("cvss") if isinstance(ent, dict) else None
                    if cvss is None:
                        continue
                    score = float(cvss)
                    if score >= 9.0:
                        critical_count_9 += 1
                    elif score >= 7.0:
                        high_count += 1
                except Exception:
                    continue

            # If we found any high/critical via management data, ensure a priority1 summary is added
            if critical_count_9 or high_count:
                priority1.append(
                    f"Kritische und hohe CVEs patchen ({critical_count_9} kritisch, {high_count} hoch identifiziert) – siehe CVE-Übersicht im Anhang."
                )
    except Exception:
        # Non-fatal: do not block recommendations if enrichment/prep fails
        pass

    # TLS weaknesses
    tls_issues = 0
    tls_issues += len((technical_json.get("tls_weaknesses") or technical_json.get("ssl_weaknesses") or []) if isinstance(technical_json, dict) else (getattr(technical_json, "tls_weaknesses", []) or []))
    for s in _iter_services(technical_json):
        si = None
        if isinstance(s, dict):
            si = s.get("ssl_info") or {}
            if si and (si.get("has_weak_cipher") or si.get("weaknesses") or si.get("issues")):
                tls_issues += 1
            if s.get("tls_weakness") or s.get("ssl_weakness"):
                tls_issues += 1
        else:
            si = getattr(s, "ssl_info", None)
            if si and (getattr(si, "has_weak_cipher", False) or getattr(si, "weaknesses", None)):
                tls_issues += 1
            if getattr(s, "tls_weakness", False) or getattr(s, "ssl_weakness", False):
                tls_issues += 1

    if tls_issues:
        priority1.append("TLS-Konfiguration überprüfen; Schwachstellen in TLS/SSL gefunden")

    # Management ports and other port-based recommendations
    mg_ports = {22: "SSH", 3389: "RDP", 5900: "VNC", 3306: "MySQL", 5432: "Postgres", 23: "Telnet", 21: "FTP"}
    found_mg = set()
    dns_on_53 = False
    has_tls_service = False
    has_web_service = False
    for s in _iter_services(technical_json):
        port = None
        prod = None
        ssl_info = None
        if isinstance(s, dict):
            port = s.get("port")
            prod = s.get("product")
            ssl_info = s.get("ssl_info") or s.get("ssl")
        else:
            port = getattr(s, "port", None)
            prod = getattr(s, "product", None)
            ssl_info = getattr(s, "ssl_info", None)

        if port == 53:
            dns_on_53 = True
        if port in {443, 8443, 9443} or ssl_info:
            has_tls_service = True
        if port in {80, 443, 8080, 8443, 8081}:
            has_web_service = True
        if port in mg_ports:
            found_mg.add(mg_ports.get(port))
        # heuristics: product names indicating DB/ssh
        if prod:
            pl = (prod or "").lower()
            if "ssh" in pl:
                found_mg.add("SSH")
            if "mysql" in pl or "postgres" in pl or "mariadb" in pl:
                found_mg.add("DB")

    for svc in sorted(found_mg):
        if svc == "SSH":
            priority2.append(
                "SSH (Port 22) sollte nicht öffentlich erreichbar sein. Empfohlen: "
                "1) Zugriff über VPN einschränken, 2) Passwort-Authentifizierung deaktivieren, "
                "nur Schlüssel, 3) Fail2ban oder ähnliche Schutzmechanismen einsetzen. "
                "Empfohlen für: Systemadministration / IT-Security-Team."
            )
        else:
            # Do not add generic 'Überprüfen' for RDP here — RDP is handled as P1 elsewhere
            if svc.upper() == "RDP":
                # skip generic RDP check
                continue
            priority2.append(f"Überprüfen: erreichbarer Managementdienst: {svc}")

    if dns_on_53:
        priority2.append("Prüfen: DNS-Server erreichbar (Port 53) – rekursive Anfragen prüfen")

    # If RDP was detected among services, ensure priority2 contains other high items
    try:
        rdp_present = False
        for s in _iter_services(technical_json):
            port = None
            prod = None
            if isinstance(s, dict):
                port = s.get("port")
                prod = (s.get("product") or "").lower()
            else:
                port = getattr(s, "port", None)
                prod = (getattr(s, "product", "") or "").lower()
            if port == 3389 or "rdp" in (prod or ""):
                rdp_present = True
                break
        if rdp_present:
            # Ensure sensible P2 items present (self-signed cert, unknown port 444 if present)
            if "Selbstsigniertes Zertifikat ersetzen" not in priority2:
                priority2.insert(0, "Selbstsigniertes Zertifikat ersetzen")
            # Mention Port 444 explicitly only if it's present; otherwise use
            # a generic phrasing to avoid asserting a port that doesn't exist.
            try:
                port444_present = any(
                    (svc.get("port") == 444 if isinstance(svc, dict) else getattr(svc, "port", None) == 444)
                    for svc in _iter_services(technical_json)
                )
            except Exception:
                port444_present = False

            if port444_present:
                txt = "Unbekannten Dienst auf Port 444 identifizieren und absichern"
            else:
                txt = "Unbekannte Dienste/ungewöhnliche Ports identifizieren und absichern"

            if txt not in priority2:
                priority2.insert(1, txt)
    except Exception:
        pass

    # Outdated/missing version heuristics
    outdated = []
    for s in _iter_services(technical_json):
        prod = None
        ver = None
        if isinstance(s, dict):
            prod = s.get("product")
            ver = s.get("version")
        else:
            prod = getattr(s, "product", None)
            ver = getattr(s, "version", None)
        if prod and (not ver or str(ver).strip().lower() in ("", "unknown")):
            outdated.append(f"Service ohne Version: {prod}")

    if outdated:
        priority2.append("Services ohne Versionsangabe: Überprüfung empfohlen")

    # Hygiene recommendations
    priority3.extend([
        "Regelmäßige Überprüfung neu auftretender Dienste",
        "Rotation und Überwachung von TLS-Zertifikaten",
    ])

    if has_tls_service:
        priority3.append("TLS-Zertifikate: Gültigkeit und Cipher-Suite regelmäßig prüfen")
    if has_web_service:
        priority3.append("Webserver: HTTP→HTTPS-Redirect konfigurieren und HSTS aktivieren")
        priority3.append("Webserver: Security-Header (X-Frame-Options, CSP) implementieren")

    return {
        "priority1": priority1,
        "priority2": priority2,
        "priority3": priority3,
        "meta": {
            # meta.critical_cves aggregates all detection paths so the
            # recommendations rendering can decide whether a "no findings"
            # placeholder is appropriate.
            "critical_cves": int(critical_count + (critical_count_9 if 'critical_count_9' in locals() else 0) + (high_count if 'high_count' in locals() else 0)),
            "tls_issues": tls_issues,
            "found_management_services": list(sorted(found_mg)),
            "dns_on_53": dns_on_53,
            "outdated_count": len(outdated),
        },
    }
