# reporting/report_validator.py
# ─────────────────────────────────────────────────────────────────────────────
# Report Logic Validator — prüft ob Score, Findings und Text konsistent sind.
#
# Aufruf:
#   from shodan_report.reporting.report_validator import validate_report
#   errors = validate_report(exposure_score, text, technical_json)
#
# Gibt eine Liste von ReportViolation zurück.
# Leere Liste = Report ist konsistent.
# ─────────────────────────────────────────────────────────────────────────────

from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class ReportViolation:
    rule: str
    message: str
    severity: str  # "ERROR" | "WARNING"

    def __str__(self) -> str:
        return f"[{self.severity}] {self.rule}: {self.message}"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_STABLE_WORDS = {"stabil", "unkritisch", "kein handlungsbedarf", "kein unmittelbarer"}
_CRITICAL_WORDS = {"sofortiger handlungsbedarf", "kritisch exponiert", "akut"}

_INSECURE_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _text_lower(text: str) -> str:
    return text.lower()


def _contains_any(text: str, words) -> bool:
    t = _text_lower(text)
    return any(w.lower() in t for w in words)


def _services(technical_json: Dict[str, Any]) -> List:
    if not technical_json:
        return []
    return technical_json.get("services") or technical_json.get("open_ports") or []


def _has_rdp(technical_json: Dict[str, Any]) -> bool:
    for s in _services(technical_json):
        port = s.get("port") if isinstance(s, dict) else getattr(s, "port", None)
        prod = (s.get("product") if isinstance(s, dict) else getattr(s, "product", "")) or ""
        if port == 3389 or "rdp" in prod.lower():
            return True
    return False


def _has_insecure_tls(technical_json: Dict[str, Any]) -> bool:
    for s in _services(technical_json):
        ssl = (s.get("ssl_info") if isinstance(s, dict) else getattr(s, "ssl_info", None)) or {}
        if isinstance(ssl, dict):
            for v in ssl.get("versions") or []:
                vs = str(v).strip()
                if not vs.startswith("-") and vs in _INSECURE_TLS:
                    return True
    return False


def _has_eol(technical_json: Dict[str, Any]) -> bool:
    try:
        from shodan_report.evaluation.eol import scan_services_for_eol
        flat = []
        for s in _services(technical_json):
            if isinstance(s, dict):
                flat.append({"port": s.get("port"), "product": s.get("product") or "",
                             "version": s.get("version") or ""})
            else:
                flat.append({"port": getattr(s, "port", None),
                             "product": getattr(s, "product", "") or "",
                             "version": getattr(s, "version", "") or ""})
        findings = scan_services_for_eol(flat)
        return any(f.get("eol_status") == "eol" for f in findings)
    except Exception:
        return False


def _cve_count(technical_json: Dict[str, Any]) -> int:
    ids: set = set()
    for s in _services(technical_json):
        cves = (s.get("vulnerabilities") if isinstance(s, dict)
                else getattr(s, "vulnerabilities", [])) or []
        for c in cves:
            cid = c.get("id") if isinstance(c, dict) else str(c)
            if cid:
                ids.add(str(cid))
    if technical_json:
        for c in (technical_json.get("vulnerabilities") or technical_json.get("vulns") or []):
            cid = c.get("id") if isinstance(c, dict) else str(c)
            if cid:
                ids.add(str(cid))
    return len(ids)


# ──────────────────────────────────────────────────────────────────────────────
# Rules
# ──────────────────────────────────────────────────────────────────────────────

def _rule_stability_vs_score(
    exposure_score: int, text: str, violations: List[ReportViolation]
) -> None:
    """Score ≥ 3 darf keinen 'stabil'-Text erzeugen."""
    if exposure_score >= 3 and _contains_any(text, _STABLE_WORDS):
        violations.append(ReportViolation(
            rule="STABILITY_SCORE_MISMATCH",
            message=(
                f"Exposure-Level {exposure_score}/5 aber Text enthält "
                f"beruhigende Formulierung ('stabil' / 'kein Handlungsbedarf'). "
                f"Erwarte erhöht/kritisch-Sprache."
            ),
            severity="ERROR",
        ))


def _rule_critical_score_vs_text(
    exposure_score: int, text: str, violations: List[ReportViolation]
) -> None:
    """Score ≥ 4 muss kritische Dringlichkeit signalisieren."""
    if exposure_score >= 4 and not _contains_any(text, _CRITICAL_WORDS | {"erhöht", "kritisch"}):
        violations.append(ReportViolation(
            rule="CRITICAL_SCORE_SOFT_TEXT",
            message=(
                f"Exposure-Level {exposure_score}/5 aber Text enthält keine "
                f"dringende Handlungsaufforderung. Erwartet: Formulierungen wie "
                f"'kritisch', 'sofortiger Handlungsbedarf' o.ä."
            ),
            severity="ERROR",
        ))


def _rule_rdp_score(
    technical_json: Dict[str, Any], exposure_score: int, violations: List[ReportViolation]
) -> None:
    """RDP öffentlich erreichbar → Exposure-Level muss ≥ 4 sein."""
    if _has_rdp(technical_json) and exposure_score < 4:
        violations.append(ReportViolation(
            rule="RDP_SCORE_MISMATCH",
            message=(
                f"RDP (Port 3389) öffentlich erreichbar, aber Exposure-Level ist "
                f"nur {exposure_score}/5. Erwarte ≥ 4."
            ),
            severity="ERROR",
        ))


def _rule_rdp_recommendation(
    technical_json: Dict[str, Any], text: str, violations: List[ReportViolation]
) -> None:
    """Bei RDP muss Text VPN oder Jumphost oder NLA erwähnen."""
    if _has_rdp(technical_json):
        if not _contains_any(text, {"vpn", "jumphost", "nla", "netzwerk access control",
                                    "ip-whitelist", "firewall"}):
            violations.append(ReportViolation(
                rule="RDP_MISSING_REMEDIATION",
                message=(
                    "RDP öffentlich erreichbar, aber Text enthält keine "
                    "konkreten Gegenmaßnahmen (VPN/Jumphost/NLA/Firewall)."
                ),
                severity="ERROR",
            ))


def _rule_eol_score(
    technical_json: Dict[str, Any], exposure_score: int, violations: List[ReportViolation]
) -> None:
    """EOL-Software → Exposure-Level muss ≥ 3 sein."""
    if _has_eol(technical_json) and exposure_score < 3:
        violations.append(ReportViolation(
            rule="EOL_UNDERSCORING",
            message=(
                f"EOL-Software erkannt, aber Exposure-Level ist nur "
                f"{exposure_score}/5. Erwarte ≥ 3."
            ),
            severity="ERROR",
        ))


def _rule_tls_score(
    technical_json: Dict[str, Any], exposure_score: int, violations: List[ReportViolation]
) -> None:
    """Unsichere TLS-Versionen → Exposure-Level muss ≥ 3 sein."""
    if _has_insecure_tls(technical_json) and exposure_score < 3:
        violations.append(ReportViolation(
            rule="TLS_UNDERSCORING",
            message=(
                f"TLS 1.0/1.1 oder SSLv3/v2 aktiv erkannt, aber Exposure-Level "
                f"ist nur {exposure_score}/5. Erwarte ≥ 3."
            ),
            severity="ERROR",
        ))


def _rule_cve_with_stable_text(
    technical_json: Dict[str, Any], text: str, violations: List[ReportViolation]
) -> None:
    """CVEs vorhanden → Text darf nicht 'keine kritischen Schwachstellen' behaupten."""
    count = _cve_count(technical_json)
    if count > 0 and "keine kritischen schwachstellen" in _text_lower(text):
        violations.append(ReportViolation(
            rule="CVE_WITH_NEGATIVE_CLAIM",
            message=(
                f"{count} CVE(s) vorhanden, aber Text behauptet "
                f"'keine kritischen Schwachstellen'."
            ),
            severity="ERROR",
        ))


def _rule_tls_text_consistency(
    technical_json: Dict[str, Any], text: str, violations: List[ReportViolation]
) -> None:
    """Wenn TLS-Probleme, darf Text nicht behaupten es gibt keine Konfigurationsrisiken."""
    if _has_insecure_tls(technical_json):
        if "keine konfigurationsrisiken" in _text_lower(text):
            violations.append(ReportViolation(
                rule="TLS_TEXT_CONTRADICTION",
                message="TLS-Schwachstellen erkannt, aber Text negiert Konfigurationsrisiken.",
                severity="ERROR",
            ))


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def validate_report(
    exposure_score: int,
    text: str,
    technical_json: Optional[Dict[str, Any]] = None,
) -> List[ReportViolation]:
    """
    Prüft ob Score, Findings und generierter Text logisch konsistent sind.

    Args:
        exposure_score:  Der finale (ggf. geboostete) Exposure-Score (1–5).
        text:            Der vollständige Management-Text des Reports.
        technical_json:  Technische Daten aus Shodan (Services, SSL, CVEs).

    Returns:
        Liste von ReportViolation — leer bedeutet: Report ist konsistent.
    """
    technical_json = technical_json or {}
    violations: List[ReportViolation] = []

    _rule_stability_vs_score(exposure_score, text, violations)
    _rule_critical_score_vs_text(exposure_score, text, violations)
    _rule_rdp_score(technical_json, exposure_score, violations)
    _rule_rdp_recommendation(technical_json, text, violations)
    _rule_eol_score(technical_json, exposure_score, violations)
    _rule_tls_score(technical_json, exposure_score, violations)
    _rule_cve_with_stable_text(technical_json, text, violations)
    _rule_tls_text_consistency(technical_json, text, violations)

    return violations
