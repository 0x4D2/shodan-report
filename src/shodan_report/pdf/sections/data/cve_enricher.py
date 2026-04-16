"""Minimal local-only CVE enricher.

This module intentionally avoids network calls. It only derives per-CVE
evidence from the provided ``technical_json`` (ports and embedded CVSS).
It provides flexible wrappers expected by other modules in the codebase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import json
import re
import time
from enum import Enum
from shodan_report.paths import cache_dir as _cache_base


# ──────────────────────────────────────────────────────────────────────────────
# Drei-Stufen-Confidence-System
# ──────────────────────────────────────────────────────────────────────────────

class MatchConfidence(Enum):
    """Beschreibt wie sicher die Zuordnung eines CVE zur gescannten Komponente ist.

    VERIFIED:  Version liegt laut NVD-cpeMatch nachweislich in einer betroffenen Range.
    INFERRED:  Dienst erkannt (CPE-Match), aber Version nicht prüfbar oder
               nicht in einer bekannten Range — CVE möglicherweise zutreffend.
    UNMATCHED: Kein CPE-Mapping möglich. CVE stammt aus Shodan-Metadaten und
               kann keinem erkannten Dienst zugeordnet werden.
    """
    VERIFIED  = "verified"
    INFERRED  = "inferred"
    UNMATCHED = "unmatched"


# VENDOR_MAP: Bildet bekannte Service-Labels (lowercase) auf den NVD-Vendor und
# NVD-Product-Namen ab. Wird für die Versions-Range-Prüfung gegen NVD-cpeMatch
# benötigt. Werte entsprechen dem CPE-2.3-Format: cpe:2.3:a:<vendor>:<product>:...
VENDOR_MAP: Dict[str, Dict[str, str]] = {
    "openssh":             {"vendor": "openssh",      "product": "openssh"},
    "apache http server":  {"vendor": "apache",       "product": "http_server"},
    "apache":              {"vendor": "apache",       "product": "http_server"},
    "nginx":               {"vendor": "nginx",        "product": "nginx"},
    "mysql":               {"vendor": "mysql",        "product": "mysql"},
    "mariadb":             {"vendor": "mariadb",      "product": "mariadb"},
    "postgresql":          {"vendor": "postgresql",   "product": "postgresql"},
    "iis":                 {"vendor": "microsoft",    "product": "internet_information_services"},
    "openssl":             {"vendor": "openssl",      "product": "openssl"},
    "postfix":             {"vendor": "wietse_venema","product": "postfix"},
    "redis":               {"vendor": "redis",        "product": "redis"},
    "php":                 {"vendor": "php",          "product": "php"},
    "vsftpd":              {"vendor": "vsftpd_project","product": "vsftpd"},
    "proftpd":             {"vendor": "proftpd",      "product": "proftpd"},
    "bind":                {"vendor": "isc",          "product": "bind"},
    "dns":                 {"vendor": "isc",          "product": "bind"},
    "dovecot":             {"vendor": "dovecot",      "product": "dovecot"},
    "exim":                {"vendor": "exim",         "product": "exim"},
    "sendmail":            {"vendor": "sendmail",     "product": "sendmail"},
    "samba":               {"vendor": "samba",        "product": "samba"},
    "clickhouse":          {"vendor": "clickhouse",   "product": "clickhouse"},
    "mongodb":             {"vendor": "mongodb",      "product": "mongodb"},
}


def _parse_version_tuple(version_str: str) -> Tuple[int, ...]:
    """Parst einen Versionsstring in ein vergleichbares Integer-Tupel.

    Beispiel: '2.4.54' → (2, 4, 54); '9.0p1' → (9, 0) (nur numerische Teile).
    Gibt ein leeres Tupel zurück wenn der String nicht parsebar ist.
    """
    try:
        parts = re.split(r"[.\-_]", str(version_str or "").strip())
        result = []
        for p in parts:
            m = re.match(r"(\d+)", p)
            if m:
                result.append(int(m.group(1)))
        return tuple(result) if result else ()
    except Exception:
        return ()


def _version_in_range(
    version: str,
    start_including: Optional[str] = None,
    start_excluding: Optional[str] = None,
    end_including: Optional[str] = None,
    end_excluding: Optional[str] = None,
) -> bool:
    """Prüft ob version in der NVD-Versions-Range liegt.

    Unterstützt alle vier NVD-Grenzen: versionStartIncluding, versionStartExcluding,
    versionEndIncluding, versionEndExcluding. Gibt True zurück wenn die Version
    innerhalb der Range liegt.
    """
    v = _parse_version_tuple(version)
    if not v:
        return False

    if start_including is not None:
        s = _parse_version_tuple(start_including)
        if s and v < s:
            return False

    if start_excluding is not None:
        s = _parse_version_tuple(start_excluding)
        if s and v <= s:
            return False

    if end_including is not None:
        e = _parse_version_tuple(end_including)
        if e and v > e:
            return False

    if end_excluding is not None:
        e = _parse_version_tuple(end_excluding)
        if e and v >= e:
            return False

    return True


def _extract_cpe_matches_for_service(
    nvd_json: Dict[str, Any],
    vendor: str,
    product: str,
) -> List[Dict[str, Any]]:
    """Extrahiert alle cpeMatch-Einträge aus nvd_json die zu vendor:product passen
    und vulnerable:true gesetzt haben.

    Wird von match_cve_to_service() für die Versions-Range-Prüfung genutzt.
    """
    matches: List[Dict[str, Any]] = []
    vendor_l  = vendor.lower().replace("_", " ")
    product_l = product.lower().replace("_", " ")

    try:
        # NVD v2-Format
        vulns = nvd_json.get("vulnerabilities") or []
        v0 = vulns[0] if isinstance(vulns, list) and vulns else {}
        configs = (
            v0.get("cve", {}).get("configurations")
            or v0.get("configurations")
            or []
        )
        # Fallback auf Legacy CVE_Items
        if not configs:
            items = (
                nvd_json.get("CVE_Items")
                or nvd_json.get("result", {}).get("CVE_Items")
                or []
            )
            if items:
                configs = items[0].get("configurations") or []

        for config in (configs if isinstance(configs, list) else []):
            for node in (config.get("nodes") or []):
                for cpe_match in (node.get("cpeMatch") or []):
                    if not bool(cpe_match.get("vulnerable", True)):
                        continue
                    criteria = cpe_match.get("criteria") or cpe_match.get("cpe23Uri") or ""
                    parts = criteria.split(":")
                    if len(parts) < 5:
                        continue
                    cpe_vendor  = parts[3].lower().replace("_", " ")
                    cpe_product = parts[4].lower().replace("_", " ")
                    # Beide müssen matchen: verhindert Fehlzuordnungen wie apache:mod_fcgid
                    # wenn wir nach apache:http_server suchen (vendor "apache" allein reicht nicht).
                    vendor_match  = vendor_l in cpe_vendor  or cpe_vendor in vendor_l
                    product_match = product_l in cpe_product or cpe_product in product_l
                    if vendor_match and product_match:
                        matches.append(cpe_match)
    except Exception:
        pass

    return matches


def match_cve_to_service(
    entry: Dict[str, Any],
    nvd_json: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Bestimmt die MatchConfidence für ein enriched CVE-Entry.

    Liest service_indicator.label und service_version aus dem Entry,
    schlägt den Dienst im VENDOR_MAP nach und prüft ggf. die NVD-Versions-Range.

    Args:
        entry:    Enriched CVE-Dict (aus enrich_cves_with_local oder enrich_cves).
        nvd_json: Rohe NVD-Antwort für dieses CVE (optional; für VERIFIED-Upgrade).

    Setzt entry["confidence"] und entry["match_note"]; gibt das Entry zurück.
    """
    service_label   = (entry.get("service_indicator") or {}).get("label") or entry.get("service")
    service_version = entry.get("service_version")
    service_cpe_raw = entry.get("service_cpe")

    # Stufe 3: weder Dienst-Label noch konkreter CPE → UNMATCHED
    if not service_label and not service_cpe_raw:
        entry["confidence"]  = MatchConfidence.UNMATCHED
        entry["match_note"]  = (
            "Kein CPE-Mapping möglich — CVE basiert auf Shodan-Metadaten "
            "und ist ohne aktive Verifikation nicht bewertbar."
        )
        return entry

    # Stufe 1: CPE direkt aus Shodan-Snapshot nutzen (präziser als VENDOR_MAP-Label-Matching).
    # service_cpe enthält den vom Shodan-Scanner gelieferten CPE-2.3-String, z.B.
    # "cpe:2.3:a:apache:http_server:2.4.66:*:*:*:*:*:*:*" → vendor=apache, product=http_server.
    # Das vermeidet False-Positives durch rein label-basiertes Matching.
    vendor_entry = _vendor_product_from_cpe(service_cpe_raw)

    # Fallback: VENDOR_MAP Label-Matching für Dienste ohne Shodan-CPE
    if not vendor_entry and service_label:
        label_lower = service_label.lower()
        for key, val in VENDOR_MAP.items():
            if key in label_lower or label_lower in key:
                vendor_entry = val
                break

    # Kein Mapping möglich → UNMATCHED
    if not vendor_entry:
        entry["confidence"] = MatchConfidence.UNMATCHED
        entry["match_note"] = (
            f"Kein CPE-Mapping für '{service_label}' — "
            "CVE ist ohne aktive Verifikation nicht bewertbar."
        )
        return entry

    # VENDOR_MAP vorhanden, aber keine Version → INFERRED
    if not service_version:
        entry["confidence"] = MatchConfidence.INFERRED
        entry["match_note"] = (
            f"Dienst '{service_label}' erkannt, "
            "Version nicht verfügbar — Versionsprüfung nicht möglich."
        )
        return entry

    # VENDOR_MAP + Version vorhanden → Versions-Range aus NVD prüfen
    if nvd_json:
        cpe_matches = _extract_cpe_matches_for_service(
            nvd_json, vendor_entry["vendor"], vendor_entry["product"]
        )
        if cpe_matches:
            for cm in cpe_matches:
                in_range = _version_in_range(
                    service_version,
                    start_including = cm.get("versionStartIncluding"),
                    start_excluding = cm.get("versionStartExcluding"),
                    end_including   = cm.get("versionEndIncluding"),
                    end_excluding   = cm.get("versionEndExcluding"),
                )
                if in_range:
                    entry["confidence"] = MatchConfidence.VERIFIED
                    entry["match_note"] = (
                        f"Version {service_version} liegt in der betroffenen "
                        f"NVD-Range für {service_label}."
                    )
                    return entry
            # Ranges gefunden, aber Version außerhalb → wahrscheinlich gepatcht
            entry["confidence"] = MatchConfidence.INFERRED
            entry["match_note"] = (
                f"Version {service_version} liegt außerhalb der bekannten "
                f"NVD-Ranges für {service_label} — möglicherweise bereits gepatcht."
            )
            return entry

    # NVD-Daten nicht verfügbar oder keine passenden Ranges → INFERRED
    entry["confidence"] = MatchConfidence.INFERRED
    entry["match_note"] = (
        f"Dienst '{service_label}' erkannt (Version {service_version}), "
        "NVD-Versionsbereiche nicht prüfbar."
    )
    return entry

try:
    from shodan_report.clients.nvd_client import NvdClient
except Exception:  # pragma: no cover - defensive for minimal environments
    NvdClient = None

try:
    from shodan_report.clients.cisa_client import CisaClient
except Exception:  # pragma: no cover - defensive for minimal environments
    CisaClient = None


def _default_cache_path() -> Path:
    p = _cache_base() / "shodan_report" / "cve_cache.json"
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


def _vendor_product_from_cpe(cpe_str: str) -> Optional[Dict[str, str]]:
    """Extrahiert vendor und product direkt aus einem CPE-2.3-String.

    cpe:2.3:a:apache:http_server:2.4.66:*:... → {"vendor": "apache", "product": "http_server"}

    Gibt None zurück wenn der String nicht parsebar oder vendor/product Wildcards sind.
    Wird von match_cve_to_service() genutzt um den VENDOR_MAP-Umweg zu vermeiden wenn
    Shodan bereits einen konkreten CPE pro Service liefert.
    """
    if not cpe_str or not isinstance(cpe_str, str):
        return None
    parts = cpe_str.split(":")
    if len(parts) < 5:
        return None
    vendor  = parts[3].lower().strip()
    product = parts[4].lower().strip()
    if not vendor  or vendor  in ("*", "-", ""):
        return None
    if not product or product in ("*", "-", ""):
        return None
    return {"vendor": vendor, "product": product}


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


# BUGFIX: Bug 2 — CPE-Plausibilitätsfilter: prüft ob ein Produkt in NVD-Konfigurationen
# als tatsächlich verwundbares Ziel (vulnerable:true) oder nur als Laufzeitplattform
# (vulnerable:false, "Running on/with"-Kontext) eingetragen ist.
def _get_cpe_vulnerable_map(nvd_json: Dict[str, Any]) -> Dict[str, bool]:
    """Liefert {produkt_lower: is_vulnerable} aus den NVD-Konfigurationen.

    Parsed cpeMatch-Einträge und gibt für jeden Produkt-/Vendor-Namen zurück,
    ob er mit vulnerable:true (True) oder ausschließlich vulnerable:false (False)
    im NVD-Datensatz steht.

    Wird in enrich_cves() genutzt um CVEs mit vulnerable:false als low_confidence
    zu markieren (Bug 2).
    """
    result: Dict[str, bool] = {}
    try:
        # NVD v2: 'vulnerabilities' key beinhaltet die rohen Daten
        vulns_v2 = nvd_json.get("vulnerabilities") or []
        v0 = vulns_v2[0] if isinstance(vulns_v2, list) and vulns_v2 else {}
        configs = (
            v0.get("cve", {}).get("configurations")
            or v0.get("configurations")
            or []
        )
        # Fallback: Legacy CVE_Items-Struktur
        if not configs:
            items = (
                nvd_json.get("CVE_Items")
                or nvd_json.get("result", {}).get("CVE_Items")
                or []
            )
            if items:
                configs = items[0].get("configurations") or []

        for config in (configs if isinstance(configs, list) else []):
            for node in (config.get("nodes") or []):
                for cpe_match in (node.get("cpeMatch") or []):
                    criteria = (
                        cpe_match.get("criteria")
                        or cpe_match.get("cpe23Uri")
                        or ""
                    )
                    # vulnerable:true ist der Default für ältere NVD-Einträge ohne Flag
                    is_vulnerable: bool = bool(cpe_match.get("vulnerable", True))
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3].lower()
                        product = parts[4].lower()
                        for name in (vendor, product):
                            if not name or name in ("*", "-"):
                                continue
                            # True "überschreibt" False: sobald ein Eintrag vulnerable:true
                            # gesehen wurde, bleibt der Status True
                            if name not in result or is_vulnerable:
                                result[name] = is_vulnerable
    except Exception:
        pass
    return result


def _is_platform_only(nvd_json: Dict[str, Any], service_label: str) -> bool:
    """Gibt True zurück wenn service_label in NVD nur als Plattform (vulnerable:false) steht.

    BUGFIX: Bug 2 — Kernprüfung des Plausibilitätsfilters. Gibt True zurück wenn:
    - Es mindestens einen cpeMatch-Eintrag gibt (NVD-Daten vollständig geladen)
    - Der gesuchte Produktname ausschließlich mit vulnerable:false eingetragen ist

    Args:
        nvd_json:       Rohdaten-Dict von fetch_cve_json()
        service_label:  Produktname wie von extract_service_from_cpe() geliefert,
                        z.B. "Apache HTTP Server", "OpenSSH", "Nginx"
    """
    if not service_label:
        return False
    vulnerable_map = _get_cpe_vulnerable_map(nvd_json)
    if not vulnerable_map:
        # Keine CPE-Daten vorhanden → keine Aussage möglich
        return False
    label_lower = service_label.lower()
    # Suche nach Teilstring-Match (z.B. "apache http server" → "apache" oder "http_server")
    for key, is_vuln in vulnerable_map.items():
        if key in label_lower or label_lower in key:
            if not is_vuln:
                # Prüfen ob irgendein anderer Eintrag vulnerable:true hat
                # (dann ist es wirklich eine Plattform-Abhängigkeit)
                has_any_vulnerable = any(v for v in vulnerable_map.values())
                return has_any_vulnerable
    return False


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

        # Zweistufige Extraktion: erst alle cpeMatch-Einträge mit vulnerable-Flag sammeln,
        # dann vulnerable:true bevorzugen statt blind den ersten Eintrag zu nehmen.
        # Hintergrund: NVD listet "Running on/with"-Plattformen (vulnerable:false) im
        # selben cpeMatch-Block wie die eigentlich betroffene Komponente. Ein blinder
        # "ersten nehmen"-Ansatz würde bei CVE-2007-4723 ggf. Apache liefern statt
        # des tatsächlich betroffenen Ragnarok Online Control Panel.
        vuln_true_cpes: list = []
        vuln_false_cpes: list = []

        def _collect_cpe_matches(obj: Any) -> None:
            """Sammelt alle cpeMatch-Einträge in vuln_true_cpes / vuln_false_cpes."""
            if isinstance(obj, dict):
                # cpeMatch-Eintrag direkt: enthält criteria/cpe23Uri + optional vulnerable
                for k in ("cpe23Uri", "cpe23", "cpe", "cpe22Uri", "criteria"):
                    val = obj.get(k)
                    if isinstance(val, str) and val.startswith("cpe:"):
                        is_vuln = bool(obj.get("vulnerable", True))  # Default True (Legacy)
                        if is_vuln:
                            vuln_true_cpes.append(val)
                        else:
                            vuln_false_cpes.append(val)
                        return  # Eintrag vollständig verarbeitet
                # Kein CPE-String direkt → Kinder rekursiv durchsuchen
                for v in obj.values():
                    _collect_cpe_matches(v)
            elif isinstance(obj, list):
                for v in obj:
                    _collect_cpe_matches(v)

        _collect_cpe_matches(configs)

        # Rückgabe: erste vulnerable:true-CPE; Fallback auf vulnerable:false
        if vuln_true_cpes:
            return vuln_true_cpes[0]
        if vuln_false_cpes:
            return vuln_false_cpes[0]
        return None
    except Exception:
        return None


def build_cve_port_map(technical_json: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Build mapping: CVE ID -> {ports, max_cvss, cpes, versions} from local snapshot.

    'versions' enthält alle Service-Versionen aus dem Snapshot, in denen diese CVE
    gelistet ist — wird von match_cve_to_service() für die VERIFIED-Prüfung genutzt.
    """
    mapping: Dict[str, Dict[str, Any]] = {}
    if not technical_json or not isinstance(technical_json, dict):
        return mapping

    services = technical_json.get("services") or technical_json.get("open_ports") or []
    for s in services:
        if isinstance(s, dict):
            port    = s.get("port")
            sv_vulns = s.get("vulnerabilities") or s.get("vuls") or s.get("vulns") or s.get("cves") or []
            cpes    = s.get("cpes") or s.get("cpe") or s.get("cpe23") or s.get("cpe23Uri") or []
            # Version aus Service-Dict: direkt oder unter verschachteltem "service"-Key
            svc_sub = s.get("service") if isinstance(s.get("service"), dict) else {}
            version = (
                s.get("version")
                or svc_sub.get("version")
                or s.get("banner_version")
                or None
            )
        else:
            port    = getattr(s, "port", None)
            sv_vulns = (
                getattr(s, "vulnerabilities", [])
                or getattr(s, "vuls", [])
                or getattr(s, "vulns", [])
                or getattr(s, "cves", [])
            )
            cpes    = (
                getattr(s, "cpes", None)
                or getattr(s, "cpe", None)
                or getattr(s, "cpe23", None)
                or getattr(s, "cpe23Uri", None)
                or []
            )
            version = getattr(s, "version", None) or None

        cpe_list = _normalize_cpes(cpes)
        version_str = str(version).strip() if version else None

        for v in sv_vulns or []:
            try:
                if isinstance(v, str):
                    cid  = v
                    cvss = None
                elif isinstance(v, dict):
                    cid  = v.get("id") or v.get("cve") or v.get("name")
                    cvss = v.get("cvss") or v.get("cvss_score")
                else:
                    cid  = getattr(v, "id", None) or getattr(v, "cve", None) or getattr(v, "name", None)
                    cvss = getattr(v, "cvss", None)
                if not cid:
                    continue
                cid = str(cid).strip()
                score = None
                try:
                    score = float(cvss) if cvss is not None else None
                except Exception:
                    score = None

                # 'versions' und 'primary_cpe' pro CVE sammeln
                ent = mapping.setdefault(cid, {"ports": [], "max_cvss": None, "cpes": [], "versions": [], "primary_cpe": None})
                if port is not None and port not in ent["ports"]:
                    ent["ports"].append(port)
                # primary_cpe: erster konkreter CPE (ohne Wildcards) des meldenden Services
                if ent["primary_cpe"] is None and cpe_list:
                    for cpe in cpe_list:
                        if _vendor_product_from_cpe(cpe) is not None:
                            ent["primary_cpe"] = cpe
                            break
                if score is not None:
                    if ent["max_cvss"] is None or score > ent["max_cvss"]:
                        ent["max_cvss"] = score
                if cpe_list:
                    for cpe in cpe_list:
                        if cpe and cpe not in ent["cpes"]:
                            ent["cpes"].append(cpe)
                if version_str and version_str not in ent["versions"]:
                    ent["versions"].append(version_str)
            except Exception:
                continue

    return mapping


def enrich_cves_with_local(technical_json: Dict[str, Any], cve_ids: List[str]) -> List[Dict[str, Any]]:
    """Enrich CVEs with local snapshot data only (ports + CVSS + initial MatchConfidence)."""
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

            # Service-Version aus Snapshot übernehmen (erste verfügbare)
            versions = pm.get("versions") or []
            if versions:
                entry["service_version"] = versions[0]

            # service_cpe: roher CPE-String aus Shodan-Snapshot — wird von
            # match_cve_to_service() für präzises Vendor/Product-Matching genutzt
            # statt dem VENDOR_MAP-Label-Matching.
            primary_cpe = pm.get("primary_cpe")
            if primary_cpe:
                entry["service_cpe"] = primary_cpe

        # Initiale Confidence ohne NVD-Daten:
        # Hat der Eintrag einen erkannten Service? → INFERRED; sonst → UNMATCHED.
        # enrich_cves() kann später auf VERIFIED upgraden wenn NVD-Ranges passen.
        entry = match_cve_to_service(entry, nvd_json=None)

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

            # BUGFIX: Bug 2 — lokales Service-Label VOR dem NVD-Service-Block sichern.
            # Die lokale Anreicherung (enrich_cves_with_local) befüllt service_indicator
            # aus Snapshot-CPEs. Der NVD-Block kann service_indicator überschreiben wenn
            # entry["service"] noch None ist. Wir brauchen aber das Snapshot-Label für
            # die _is_platform_only-Prüfung — daher hier vor dem NVD-Block fixieren.
            _local_service_label = (entry.get("service_indicator") or {}).get("label")

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

            # BUGFIX: Bug 2 — Plausibilitätsfilter: prüfen ob die GESCANNTE Komponente
            # (aus dem lokalen Snapshot, CPE-abgeleitet) in NVD nur als Plattform
            # (vulnerable:false, "Running on/with"-Kontext) eingetragen ist.
            # Wir nutzen _local_service_label (Snapshot), nicht den NVD-abgeleiteten
            # Service — denn wir wollen wissen ob die gescannte Komponente Plattform ist.
            _check_service = _local_service_label or nvd_service
            if _check_service and _is_platform_only(nvd_json or {}, _check_service):
                entry["low_confidence"] = True
                entry["low_confidence_reason"] = (
                    f"{_check_service} ist in NVD nur als Laufzeitplattform "
                    f"(vulnerable:false) eingetragen, nicht als verwundbare Komponente."
                )
                # Confidence in service_indicator aktualisieren
                if isinstance(entry.get("service_indicator"), dict):
                    entry["service_indicator"]["confidence"] = "low_confidence"

            # Drei-Stufen-Confidence: match_cve_to_service mit vollem nvd_json aufrufen.
            # Jetzt können Versions-Ranges aus NVD geprüft werden → ggf. VERIFIED.
            # Nur upgraden wenn noch nicht low_confidence (Bug 2) gesetzt.
            if not entry.get("low_confidence"):
                entry = match_cve_to_service(entry, nvd_json=nvd_json)

            if nvd_fields.get("summary") or nvd_fields.get("cvss") or nvd_fields.get("service"):
                entry.setdefault("sources", []).append("nvd")
        except Exception:
            continue

    if lookup_nvd:
        _save_cache(cache, cache_path)

    return enriched

