from typing import Any, Dict, List, Tuple

from shodan_report.pdf.sections.data.recommendations_data import prepare_recommendations_data


def risk_status(business_risk: Any) -> str:
    risk_value = str(business_risk or "").strip().lower()
    if risk_value in {"critical", "high"}:
        return "action_required"
    if risk_value in {"medium", "attention"}:
        return "watch"
    return "stable"


def _iter_services(technical_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(technical_json.get("services") or technical_json.get("open_ports") or [])


def collect_positive_points(technical_json: Dict[str, Any], greynoise: Dict[str, Any]) -> List[str]:
    services = _iter_services(technical_json or {})
    positives: List[str] = []

    has_tls = False
    insecure_tls = False
    valid_cert = False
    for service in services:
        if not isinstance(service, dict):
            continue
        tls = service.get("tls") or {}
        ssl_info = service.get("ssl_info") or {}
        versions = ssl_info.get("versions") or []
        if tls or ssl_info:
            has_tls = True
        if tls.get("cert_expiry") or tls.get("cert_valid_to"):
            valid_cert = True
        for version in versions:
            version_text = str(version).strip()
            if version_text in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
                insecure_tls = True

    if has_tls and not insecure_tls:
        positives.append("TLS ist auf den erkannten Diensten aktiv und ohne offensichtliche Altprotokolle sichtbar.")
    if valid_cert:
        positives.append("Mindestens ein öffentlich sichtbares Zertifikat liegt mit Ablaufdatum vor und ist damit nachvollziehbar verwaltet.")

    gn_classification = str((greynoise or {}).get("classification") or "").strip().lower()
    if (greynoise or {}).get("available") and (gn_classification == "benign" or not (greynoise or {}).get("noise", False)):
        positives.append("GreyNoise stuft die IP aktuell als CLEAN beziehungsweise unauffällig ein.")

    cve_enriched = (technical_json or {}).get("cve_enriched") or []
    critical_cves = 0
    for entry in cve_enriched:
        if not isinstance(entry, dict):
            continue
        try:
            if float(entry.get("cvss") or 0) >= 9.0:
                critical_cves += 1
        except Exception:
            continue
    if critical_cves == 0:
        positives.append("In den angereicherten Daten wurden keine kritisch bewerteten CVEs mit CVSS ab 9 gefunden.")

    if not positives:
        positives.append("Es wurden keine akuten, bereits bestätigten Sofortbefunde aus den vorliegenden OSINT-Daten abgeleitet.")

    return positives[:3]


def _format_action(action: Dict[str, Any]) -> str:
    title = str(action.get("title") or "").strip()
    what = str(action.get("what") or "").strip()
    evidence = str(action.get("evidence") or "").strip().upper()
    deadline = str(action.get("deadline") or "").strip()
    duration = action.get("duration_minutes")
    cost_min = action.get("cost_min")
    cost_max = action.get("cost_max")
    line = f"<b>{title}</b>" if title else ""
    if what:
        line = f"{line}: {what}" if line else what
    extras: List[str] = []
    if deadline:
        extras.append(f"Frist {deadline}")
    if isinstance(duration, int) and duration > 0:
        extras.append(f"ca. {duration} Min")
    if isinstance(cost_min, int) and isinstance(cost_max, int):
        if cost_min == cost_max:
            extras.append(f"{cost_min} EUR")
        else:
            extras.append(f"{cost_min}-{cost_max} EUR")
    if extras:
        line = f"{line} <font color=\"#6B7280\">({' | '.join(extras)})</font>"
    if evidence:
        line = f"{line} <font color=\"#6B7280\">({evidence})</font>"
    return line or str(action.get("text") or "")


def prepare_executive_summary_data(ctx: Any) -> Dict[str, Any]:
    config = getattr(ctx, "config", {}) or {}
    cover_note = str(((config.get("report") or {}).get("cover_note") or "")).strip()
    management_text = str(getattr(ctx, "management_text", "") or "").strip()
    buckets = prepare_recommendations_data(
        getattr(ctx, "technical_json", {}) or {},
        getattr(ctx, "evaluation", {}) or {},
        getattr(ctx, "business_risk", "MEDIUM"),
    )

    recommendation_groups: List[Tuple[str, List[str], str]] = [
        (
            "Sofort",
            [_format_action(action) for action in list(buckets.get("priority1_actions") or [])[:1]] or list(buckets.get("priority1") or [])[:1],
            "#B91C1C",
        ),
        (
            "Empfohlen",
            [_format_action(action) for action in list(buckets.get("priority2_actions") or [])[:2]] or list(buckets.get("priority2") or [])[:2],
            "#B45309",
        ),
        (
            "Optional",
            [_format_action(action) for action in list(buckets.get("priority3_actions") or [])[:1]] or list(buckets.get("priority3") or [])[:1],
            "#15803D",
        ),
    ]

    return {
        "status_key": risk_status(getattr(ctx, "business_risk", None)),
        "summary_text": cover_note or management_text or "Keine Management-Zusammenfassung verfügbar.",
        "positive_points": collect_positive_points(
            getattr(ctx, "technical_json", {}) or {},
            getattr(ctx, "greynoise", None) or {},
        ),
        "recommendation_groups": recommendation_groups,
    }