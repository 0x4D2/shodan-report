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

    # ── EOL-Detection: steht vor CVEs in P1 ───────────────────────────────
    try:
        from shodan_report.evaluation.eol import scan_services_for_eol as _scan_eol_rec
        _flat_for_eol = []
        for _s in _iter_services(technical_json):
            if not isinstance(_s, dict):
                continue
            _sub = _s.get("service") or {}
            _flat_for_eol.append({
                "port":    _s.get("port"),
                "product": _s.get("product") or _sub.get("product") or "",
                "version": _s.get("version") or _sub.get("version") or "",
            })
        for _f in _scan_eol_rec(_flat_for_eol):
            _status = _f.get("eol_status", "")
            _name = _f.get("display_name") or "Unbekanntes Produkt"
            _eol_date = _f.get("eol_date") or ""
            _model = _f.get("support_model", "official")
            _qualifier = " (lizenzabhängig)" if _model == "mainstream_end" else ""
            if _status == "eol":
                priority1.append(
                    f"<b>EOL-System</b> ersetzen oder isolieren: <b>{_name}</b>{_qualifier} — "
                    "Sicherheits-Support beendet; keine regulären Patches mehr verfügbar. "
                    "Migration auf unterstützte Version einleiten."
                )
            elif _status == "near_eol" and _eol_date:
                priority1.append(
                    f"<b>EOL-Migration</b> planen: <b>{_name}</b> — Support endet <b>{_eol_date}</b>. "
                    "Migrationsprojekt jetzt starten."
                )
    except Exception:
        pass

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

    # Deduplicate CVEs by ID and count high/critical using thresholds matching cve_overview:
    # critical >= 9.0, high 7.0–8.9
    _cve_by_id: dict = {}
    for cv in cves:
        try:
            if isinstance(cv, dict):
                cid = cv.get("id") or cv.get("cve") or cv.get("name")
                cvss = float(cv.get("cvss") or 0)
            else:
                cid = str(cv).strip()
                cvss = 0.0
            if not cid:
                continue
            cid = str(cid).strip()
            # keep highest CVSS seen for each ID
            if cid not in _cve_by_id or cvss > _cve_by_id[cid]:
                _cve_by_id[cid] = cvss
        except Exception:
            continue

    # Also fold in any pre-enriched CVE lists so CVSS values are populated
    try:
        enriched_candidates = []
        if isinstance(technical_json, dict):
            enriched_candidates = technical_json.get("cve_enriched") or technical_json.get("cve_enriched_sample") or technical_json.get("cve_enriched_list") or []
        if not enriched_candidates and isinstance(evaluation, dict):
            enriched_candidates = evaluation.get("cve_enriched") or evaluation.get("cve_enriched_sample") or []
        for ent in (enriched_candidates or []):
            try:
                if isinstance(ent, dict):
                    cid = ent.get("id") or ent.get("cve") or ent.get("name")
                    cvss = float(ent.get("cvss") or 0)
                else:
                    continue
                if not cid:
                    continue
                cid = str(cid).strip()
                if cid not in _cve_by_id or cvss > _cve_by_id[cid]:
                    _cve_by_id[cid] = cvss
            except Exception:
                continue
    except Exception:
        pass

    _critical_7_count = sum(1 for v in _cve_by_id.values() if v >= 9.0)
    _high_count = sum(1 for v in _cve_by_id.values() if 7.0 <= v < 9.0)

    # ExploitDB-Treffer aus technical_json lesen
    _exploit_map = technical_json.get("cve_exploit_map") or {} if isinstance(technical_json, dict) else {}
    _epss_map    = technical_json.get("cve_epss_map")    or {} if isinstance(technical_json, dict) else {}
    _n_exploitdb = sum(1 for v in _exploit_map.values() if v)
    _epss_max    = max((_epss_map.values()), default=None)

    if _critical_7_count or _high_count:
        _exploit_suffix = f" — <b>{_n_exploitdb} mit öffentlichem Exploit (ExploitDB)</b>" if _n_exploitdb else ""
        _epss_suffix    = f", EPSS max. {_epss_max * 100:.0f}%" if _epss_max and _epss_max >= 0.05 else ""
        priority1.append(
            f"<b>CVEs patchen:</b> {_critical_7_count} kritisch (CVSS ≥9), {_high_count} hoch (CVSS 7–8.9)"
            f"{_exploit_suffix}{_epss_suffix} – Details in CVE-Übersicht."
        )
    elif _cve_by_id:
        priority1.append(f"<b>CVEs analysieren:</b> {len(_cve_by_id)} Schwachstellen identifiziert – CVSS-Bewertung ausstehend.")

    # Additionally, include CVEs discovered via management data / unique_cves
    # (kept for fallback enrichment but no longer adds duplicate priority1 items)
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

        if management_cves and not _cve_by_id:
            # Only use management data as fallback when the initial CVE collection was empty
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
                    f"<b>CVEs patchen:</b> {critical_count_9} kritisch (CVSS ≥9), {high_count} hoch (CVSS 7–8.9) – siehe CVE-Übersicht im Anhang."
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

    # Check ssl_info.versions for actively enabled insecure TLS/SSL protocols
    _tls_insecure_vers = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    _found_insecure_tls: set = set()
    for s in _iter_services(technical_json):
        if isinstance(s, dict):
            ssl_info = s.get("ssl_info") or {}
            if isinstance(ssl_info, dict):
                for ver in (ssl_info.get("versions") or []):
                    ver_str = str(ver).strip()
                    if not ver_str.startswith("-") and ver_str in _tls_insecure_vers:
                        _found_insecure_tls.add(ver_str)
                        tls_issues += 1

    if tls_issues:
        if _found_insecure_tls:
            protos = ", ".join(sorted(_found_insecure_tls))
            priority1.append(
                f"<b>TLS-Konfiguration:</b> Unsichere Protokolle aktiv (<b>{protos}</b>) — sofort deaktivieren"
            )
        else:
            priority1.append("<b>TLS-Konfiguration</b> überprüfen — Schwachstellen in TLS/SSL gefunden")

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
            priority2.append("<b>SSH</b> (<b>Port 22</b>) ist öffentlich erreichbar — Zugriff einschränken")
            priority2.append("Zugriff ausschließlich über <b>VPN</b> oder <b>Jump-Host</b> erlauben")
            priority2.append("<b>Passwort-Authentifizierung</b> deaktivieren, nur <b>SSH-Schlüssel</b> zulassen")
            priority2.append("<b>Brute-Force-Schutz</b> einrichten (z. B. <b>Fail2ban</b>)")
        else:
            if svc.upper() == "RDP":
                continue
            priority2.append(f"<b>{svc}</b> einschränken — Managementdienst öffentlich erreichbar")

    if dns_on_53:
        priority2.append("<b>DNS</b> (<b>Port 53</b>) erreichbar — rekursive Anfragen prüfen")

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
        "TLS-Zertifikate: Gültigkeit, Ablauf und Cipher-Suite regelmäßig prüfen",
    ])
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
            "critical_cves": int(_critical_7_count + _high_count),
            "tls_issues": tls_issues,
            "found_management_services": list(sorted(found_mg)),
            "dns_on_53": dns_on_53,
            "outdated_count": len(outdated),
        },
    }
