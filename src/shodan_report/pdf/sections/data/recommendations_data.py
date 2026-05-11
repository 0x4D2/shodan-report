import re
from datetime import datetime
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


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", str(text or "")).strip()


def _slugify(text: str) -> str:
    plain = _strip_html(text).lower()
    plain = re.sub(r"[^a-z0-9]+", "-", plain).strip("-")
    return plain or "recommendation"


def _parse_cert_date(raw: str):
    if not raw:
        return None
    value = str(raw).strip()
    for fmt in ("%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def _make_action(
    *,
    priority: str,
    title: str,
    what: str,
    evidence: str,
    source: str,
    why: str = None,
    how: str = None,
    deadline: str = None,
    deadline_type: str = "recommended",
    duration_minutes: int = None,
    cost_min: int = None,
    cost_max: int = None,
    currency: str = "EUR",
    action_id: str = None,
    text: str = None,
) -> Dict[str, Any]:
    plain_title = _strip_html(title) or _strip_html(what)
    plain_what = _strip_html(what)
    return {
        "id": action_id or f"{priority}-{_slugify(plain_title)[:48]}",
        "priority": priority,
        "title": plain_title,
        "text": text,
        "what": plain_what,
        "why": why,
        "how": how,
        "deadline": deadline,
        "deadline_type": deadline_type,
        "duration_minutes": duration_minutes,
        "cost_min": cost_min,
        "cost_max": cost_max,
        "currency": currency,
        "evidence": evidence,
        "source": source,
    }


def _action_to_text(action: Dict[str, Any]) -> str:
    if action.get("text"):
        return str(action["text"])

    title = _strip_html(action.get("title") or action.get("what") or "Empfehlung")
    what = _strip_html(action.get("what") or "")
    why = _strip_html(action.get("why") or "")

    text = f"<b>{title}</b>"
    if what and what != title:
        text += f": {what}"
    if why:
        text += f" — {why}"
    return text


def _add_action(bucket: List[Dict[str, Any]], **kwargs) -> None:
    bucket.append(_make_action(**kwargs))


def _service_label(service: Dict[str, Any]) -> str:
    product = _strip_html(service.get("product") or "")
    if product:
        return product
    port = service.get("port")
    return f"Port {port}" if port is not None else "Dienst"


def prepare_recommendations_data(technical_json: Dict[str, Any], evaluation: Any, business_risk: str) -> Dict[str, Any]:
    """Prepare prioritized recommendation buckets from snapshot + evaluation.

    Heuristics used:
    - Priority 1: critical CVEs (cvss>=7) or TLS weaknesses
    - Priority 2: management ports reachable (SSH/RDP/DB), missing certs on 443, DNS port 53
    - Priority 3: hygiene / optional items
    """
    priority1_actions: List[Dict[str, Any]] = []
    priority2_actions: List[Dict[str, Any]] = []
    priority3_actions: List[Dict[str, Any]] = []

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
                _add_action(
                    priority1_actions,
                    priority="critical",
                    action_id=f"critical-eol-{_slugify(_name)}",
                    title=f"{_name} ersetzen oder isolieren",
                    what=f"EOL-System {_name}{_qualifier} ersetzen oder bis zur Ablösung isolieren.",
                    why="Sicherheits-Support beendet; keine regulären Patches mehr verfügbar.",
                    how="Migration auf unterstützte Version einleiten oder Zugriff bis dahin einschränken.",
                    evidence="INFERRED",
                    source="eol_detection",
                    text=(
                        f"<b>EOL-System</b> ersetzen oder isolieren: <b>{_name}</b>{_qualifier} — "
                        "Sicherheits-Support beendet; keine regulären Patches mehr verfügbar. "
                        "Migration auf unterstützte Version einleiten."
                    ),
                )
            elif _status == "near_eol" and _eol_date:
                _add_action(
                    priority1_actions,
                    priority="critical",
                    action_id=f"critical-near-eol-{_slugify(_name)}",
                    title=f"Migration für {_name} planen",
                    what=f"Für {_name} endet der Support am {_eol_date}; Migrationsprojekt jetzt starten.",
                    why="Das Zeitfenster bis Support-Ende ist begrenzt.",
                    how="Ablösung mit Betreiber oder Provider terminieren.",
                    deadline=_eol_date,
                    deadline_type="fix",
                    evidence="INFERRED",
                    source="eol_detection",
                    text=(
                        f"<b>EOL-Migration</b> planen: <b>{_name}</b> — Support endet <b>{_eol_date}</b>. "
                        "Migrationsprojekt jetzt starten."
                    ),
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
        _add_action(
            priority1_actions,
            priority="critical",
            action_id="critical-patch-cves",
            title="Kritische und hohe CVEs patchen",
            what=f"{_critical_7_count} kritisch (CVSS ≥9), {_high_count} hoch (CVSS 7–8.9){_exploit_suffix}{_epss_suffix}",
            why="Es liegen Schwachstellenhinweise mit technischem Risiko vor.",
            how="Betroffene Systeme und Softwarestände mit Herstellerhinweisen und Patchstand abgleichen.",
            evidence="INFERRED",
            source="cve_aggregation",
            text=(
                f"<b>CVEs patchen:</b> {_critical_7_count} kritisch (CVSS ≥9), {_high_count} hoch (CVSS 7–8.9)"
                f"{_exploit_suffix}{_epss_suffix} – Details in CVE-Übersicht."
            ),
        )
    elif _cve_by_id:
        _add_action(
            priority1_actions,
            priority="critical",
            action_id="critical-analyze-cves",
            title="CVEs analysieren",
            what=f"{len(_cve_by_id)} Schwachstellen identifiziert; CVSS-Bewertung steht noch aus.",
            why="Es liegen Schwachstellenhinweise vor, aber noch keine belastbare Priorisierung.",
            how="Versionen und Produkte mit dem internen Bestand abgleichen.",
            evidence="INFERRED",
            source="cve_aggregation",
            text=f"<b>CVEs analysieren:</b> {len(_cve_by_id)} Schwachstellen identifiziert – CVSS-Bewertung ausstehend.",
        )

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
                _add_action(
                    priority1_actions,
                    priority="critical",
                    action_id="critical-patch-cves-fallback",
                    title="CVE-Hinweise verifizieren und patchen",
                    what=f"{critical_count_9} kritisch (CVSS ≥9), {high_count} hoch (CVSS 7–8.9) – siehe CVE-Übersicht im Anhang.",
                    why="Auch ohne angereicherte Primärdaten liegen Hinweise auf relevante Schwachstellen vor.",
                    how="CVE-Liste mit betroffenen Hosts und Softwareständen abgleichen.",
                    evidence="INFERRED",
                    source="management_cve_fallback",
                    text=f"<b>CVEs patchen:</b> {critical_count_9} kritisch (CVSS ≥9), {high_count} hoch (CVSS 7–8.9) – siehe CVE-Übersicht im Anhang.",
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

    # Ablaufende Zertifikate als separate, belastbare Aktion mit fixer Frist
    today = datetime.utcnow().date()
    for s in _iter_services(technical_json):
        if not isinstance(s, dict):
            continue
        tls = s.get("tls") or {}
        expiry_raw = tls.get("cert_expiry") or tls.get("cert_valid_to")
        expiry_date = _parse_cert_date(expiry_raw)
        if not expiry_date:
            continue
        days_until_expiry = tls.get("cert_expires_in_days")
        if not isinstance(days_until_expiry, int):
            days_until_expiry = (expiry_date - today).days
        if days_until_expiry > 45:
            continue

        service_name = _service_label(s)
        port = s.get("port")
        priority = "critical" if days_until_expiry <= 14 else "recommended"
        prefix = "critical" if priority == "critical" else "recommended"
        when_text = "ist abgelaufen" if days_until_expiry < 0 else f"laeuft am {expiry_date.isoformat()} ab"
        _add_action(
            priority1_actions if priority == "critical" else priority2_actions,
            priority=priority,
            action_id=f"{prefix}-renew-cert-{port or 'service'}",
            title=f"Zertifikat fuer {service_name} erneuern",
            what=f"Das Zertifikat auf Port {port} {when_text}.",
            why="Nach Ablauf drohen Browser-, Mail- oder Verbindungswarnungen und Betriebsstoerungen.",
            how="Zertifikat beim Provider oder ueber die bestehende PKI erneuern und bereitstellen.",
            deadline=expiry_date.isoformat(),
            deadline_type="fix",
            duration_minutes=30,
            cost_min=0,
            cost_max=50,
            evidence="VERIFIED",
            source="tls_certificate_scan",
            text=(
                f"<b>Zertifikat erneuern:</b> {service_name} auf <b>Port {port}</b> {when_text}."
            ),
        )

    if tls_issues:
        if _found_insecure_tls:
            protos = ", ".join(sorted(_found_insecure_tls))
            _add_action(
                priority1_actions,
                priority="critical",
                action_id="critical-disable-insecure-tls",
                title="Unsichere TLS-Protokolle deaktivieren",
                what=f"Unsichere Protokolle aktiv ({protos}) — sofort deaktivieren.",
                why="Die sichtbare TLS-Konfiguration erhöht die Angriffsfläche oder sollte gehärtet werden.",
                how="TLS-Konfiguration am Dienst oder Reverse Proxy auf aktuelle Protokolle und Cipher beschränken.",
                duration_minutes=45,
                cost_min=0,
                cost_max=0,
                evidence="VERIFIED",
                source="tls_protocol_scan",
                text=f"<b>TLS-Konfiguration:</b> Unsichere Protokolle aktiv (<b>{protos}</b>) — sofort deaktivieren",
            )
        else:
            _add_action(
                priority1_actions,
                priority="critical",
                action_id="critical-review-tls",
                title="TLS-Konfiguration prüfen",
                what="Schwachstellen in TLS/SSL gefunden.",
                why="Die sichtbare TLS-Konfiguration erhöht die Angriffsfläche oder sollte gehärtet werden.",
                how="TLS-Konfiguration am Dienst oder Reverse Proxy auf aktuelle Protokolle und Cipher beschränken.",
                duration_minutes=45,
                cost_min=0,
                cost_max=0,
                evidence="VERIFIED",
                source="tls_protocol_scan",
                text="<b>TLS-Konfiguration</b> überprüfen — Schwachstellen in TLS/SSL gefunden",
            )

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
            _add_action(
                priority1_actions,
                priority="critical",
                action_id="critical-harden-ssh",
                title="SSH-Zugriff kurzfristig absichern",
                what="Öffentlich erreichbaren SSH-Dienst härten.",
                why="Öffentlich erreichbare Administrationsdienste vergrößern die externe Angriffsfläche.",
                how="IP-Whitelist, Key-Only Auth und Fail2ban aktivieren; mittelfristig Zugriff hinter VPN verlegen.",
                duration_minutes=60,
                cost_min=0,
                cost_max=0,
                evidence="VERIFIED",
                source="service_detection",
                text=(
                    "<b>SSH (Port 22) kurzfristig absichern</b> — Verified Finding, direkter Angriffsvektor: "
                    "Brute-Force, Credential Stuffing. "
                    "Sofortmaßnahmen: <b>IP-Whitelist</b> · <b>Key-Only Auth</b> · <b>Fail2ban</b>. "
                    "Mittelfristig: Zugriff hinter <b>VPN-Gateway</b> verlegen."
                ),
            )
        else:
            if svc.upper() == "RDP":
                continue
            _add_action(
                priority2_actions,
                priority="recommended",
                action_id=f"recommended-restrict-{_slugify(svc)}",
                title=f"{svc}-Zugriff einschränken",
                what=f"Managementdienst {svc} ist öffentlich erreichbar.",
                why="Öffentlich erreichbare Administrationsdienste vergrößern die externe Angriffsfläche.",
                how="Zugriff auf bekannte Quellnetze begrenzen oder hinter VPN/Jumphost verlagern.",
                duration_minutes=45,
                cost_min=0,
                cost_max=0,
                evidence="VERIFIED",
                source="service_detection",
                text=f"<b>{svc}</b> einschränken — Managementdienst öffentlich erreichbar",
            )

    if dns_on_53:
        _add_action(
            priority2_actions,
            priority="recommended",
            action_id="recommended-review-dns-recursion",
            title="DNS-Rekursion prüfen",
            what="DNS auf Port 53 ist erreichbar.",
            why="Offene oder unnötige Rekursion kann missbraucht werden.",
            how="Resolver- und Rekursionskonfiguration des DNS-Dienstes prüfen.",
            duration_minutes=30,
            cost_min=0,
            cost_max=0,
            evidence="VERIFIED",
            source="service_detection",
            text="<b>DNS</b> (<b>Port 53</b>) erreichbar — rekursive Anfragen prüfen",
        )

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
            if not any(a.get("title") == "Selbstsigniertes Zertifikat ersetzen" for a in priority2_actions):
                priority2_actions.insert(0, _make_action(
                    priority="recommended",
                    action_id="recommended-replace-self-signed-cert",
                    title="Selbstsigniertes Zertifikat ersetzen",
                    what="Selbstsigniertes Zertifikat durch vertrauenswürdiges Zertifikat ersetzen.",
                    why="Selbstsignierte Zertifikate erschweren Vertrauensprüfung und sauberen Betrieb.",
                    how="Zertifikat bei Provider oder interner PKI erneuern und ausrollen.",
                    duration_minutes=30,
                    cost_min=0,
                    cost_max=50,
                    evidence="INFERRED",
                    source="rdp_follow_up",
                    text="Selbstsigniertes Zertifikat ersetzen",
                ))
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

            if not any(a.get("text") == txt for a in priority2_actions):
                priority2_actions.insert(1, _make_action(
                    priority="recommended",
                    action_id="recommended-review-unusual-service",
                    title="Ungewöhnliche Dienste prüfen",
                    what=txt,
                    why="Ungewöhnliche oder nicht eindeutig identifizierte Ports sollten einem klaren Zweck zugeordnet sein.",
                    how="Dienst zuordnen und bei fehlendem Bedarf abschalten oder absichern.",
                    evidence="VERIFIED",
                    source="service_detection",
                    text=txt,
                ))
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
        _add_action(
            priority2_actions,
            priority="recommended",
            action_id="recommended-review-missing-versions",
            title="Dienste ohne Versionsangabe prüfen",
            what="Für einzelne sichtbare Dienste fehlt eine belastbare Versionsangabe.",
            why="Ohne Version ist keine belastbare Einschätzung zu Support- und Patchstand möglich.",
            how="Banner, Systeminventar oder Provider-Angaben mit dem sichtbaren Dienst abgleichen.",
            evidence="INFERRED",
            source="service_inventory",
            text="Services ohne Versionsangabe: Überprüfung empfohlen",
        )

    # Hygiene recommendations
    _add_action(
        priority3_actions,
        priority="optional",
        action_id="optional-review-new-services",
        title="Neu auftretende Dienste regelmäßig prüfen",
        what="Regelmäßige Überprüfung neu auftretender Dienste.",
        why="So fallen Änderungen der Angriffsfläche früh auf.",
        how="Monatlichen Review-Prozess oder wiederkehrenden Report einplanen.",
        evidence="ASSUMPTION",
        source="hygiene_baseline",
        text="Regelmäßige Überprüfung neu auftretender Dienste",
    )
    _add_action(
        priority3_actions,
        priority="optional",
        action_id="optional-review-tls-certs",
        title="TLS-Zertifikate regelmäßig prüfen",
        what="Gültigkeit, Ablauf und Cipher-Suite regelmäßig prüfen.",
        why="Abgelaufene Zertifikate und veraltete Cipher-Konfigurationen verursachen Betriebs- und Sicherheitsrisiken.",
        how="Wiederkehrenden Termin oder Monitoring für Zertifikats- und TLS-Review einführen.",
        evidence="ASSUMPTION",
        source="hygiene_baseline",
        text="TLS-Zertifikate: Gültigkeit, Ablauf und Cipher-Suite regelmäßig prüfen",
    )
    if has_web_service:
        _add_action(
            priority3_actions,
            priority="optional",
            action_id="optional-enforce-https",
            title="HTTPS konsequent erzwingen",
            what="HTTP→HTTPS-Redirect konfigurieren und HSTS aktivieren.",
            why="Das reduziert unverschlüsselte Zugriffe und Mischkonfigurationen.",
            how="Redirect-Regeln und HSTS-Header im Webserver oder Proxy aktivieren.",
            evidence="ASSUMPTION",
            source="web_hardening",
            text="Webserver: HTTP→HTTPS-Redirect konfigurieren und HSTS aktivieren",
        )
        _add_action(
            priority3_actions,
            priority="optional",
            action_id="optional-add-security-headers",
            title="Security-Header ergänzen",
            what="Security-Header (X-Frame-Options, CSP) implementieren.",
            why="Diese Header reduzieren typische Browser-basierte Angriffsflächen.",
            how="Security-Header im Webserver oder Reverse Proxy definieren und mit Anwendung testen.",
            evidence="ASSUMPTION",
            source="web_hardening",
            text="Webserver: Security-Header (X-Frame-Options, CSP) implementieren",
        )

    priority1 = [_action_to_text(action) for action in priority1_actions]
    priority2 = [_action_to_text(action) for action in priority2_actions]
    priority3 = [_action_to_text(action) for action in priority3_actions]

    return {
        "priority1": priority1,
        "priority2": priority2,
        "priority3": priority3,
        "priority1_actions": priority1_actions,
        "priority2_actions": priority2_actions,
        "priority3_actions": priority3_actions,
        "meta": {
            # meta.critical_cves aggregates all detection paths so the
            # recommendations rendering can decide whether a "no findings"
            # placeholder is appropriate.
            "critical_cves": int(_critical_7_count + _high_count),
            "tls_issues": tls_issues,
            "found_management_services": list(sorted(found_mg)),
            "dns_on_53": dns_on_53,
            "outdated_count": len(outdated),
            "action_count": len(priority1_actions) + len(priority2_actions) + len(priority3_actions),
        },
    }
