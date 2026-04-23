"""
HaveIBeenPwned Client.

Zwei Modi:
  - Mit HIBP_API_KEY: echte API-Abfrage (/breachedaccount/{email})
  - Ohne Key: Link-Generierung für manuelle Prüfung im Report

Standard-Adressen werden aus der Domain abgeleitet.
Zusätzliche Adressen kommen aus config.hibp.extra_emails.
Non-fatal: leeres Ergebnis bei Fehler.
"""

import os
import time
from typing import Dict, List, Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

_API_BASE  = "https://haveibeenpwned.com/api/v3"
_TIMEOUT   = 10
_USER_AGENT = "shodan-report/1.0"

_STANDARD_PREFIXES = ["info", "admin", "support", "kontakt", "hallo", "hello", "mail"]


def _build_email_list(domain: str, extra_emails: Optional[List[str]] = None) -> List[str]:
    """Erzeugt Standard-Adressen aus Domain + optionale Extra-Adressen aus Config."""
    emails = [f"{p}@{domain}" for p in _STANDARD_PREFIXES]
    for addr in (extra_emails or []):
        addr = str(addr).strip()
        if addr and addr not in emails:
            emails.append(addr)
    return emails


def check_breaches(
    domain: str,
    extra_emails: Optional[List[str]] = None,
    api_key: Optional[str] = None,
) -> Dict[str, object]:
    """
    Prüft E-Mail-Adressen gegen HIBP.

    Rückgabe:
      {
        "mode": "api" | "manual",
        "emails": [
          {
            "email": "info@example.com",
            "breached": True | False | None,   # None = nicht geprüft (manual mode)
            "breach_count": 3,                  # nur im API-Modus
            "breach_names": ["LinkedIn", ...],  # nur im API-Modus
            "check_url": "https://haveibeenpwned.com/account/info%40example.com",
          },
          ...
        ],
        "total_breached": 2,   # Anzahl betroffener Adressen (API-Modus) oder None
      }
    """
    if not domain:
        return {"mode": "manual", "emails": [], "total_breached": None}

    _api_key = api_key or os.environ.get("HIBP_API_KEY", "")
    emails   = _build_email_list(domain, extra_emails)

    if _api_key and _HAS_REQUESTS:
        return _check_via_api(emails, _api_key)
    else:
        return _build_manual_result(emails)


def _check_via_api(emails: List[str], api_key: str) -> Dict:
    results = []
    total_breached = 0

    for email in emails:
        try:
            resp = _requests.get(
                f"{_API_BASE}/breachedaccount/{email}",
                headers={
                    "hibp-api-key": api_key,
                    "User-Agent": _USER_AGENT,
                },
                params={"truncateResponse": "false"},
                timeout=_TIMEOUT,
            )
            if resp.status_code == 200:
                breaches = resp.json()
                breach_names = [b.get("Name", "") for b in breaches]
                results.append({
                    "email":        email,
                    "breached":     True,
                    "breach_count": len(breaches),
                    "breach_names": breach_names,
                    "check_url":    _hibp_url(email),
                })
                total_breached += 1
            elif resp.status_code == 404:
                results.append({
                    "email":        email,
                    "breached":     False,
                    "breach_count": 0,
                    "breach_names": [],
                    "check_url":    _hibp_url(email),
                })
            else:
                results.append(_manual_entry(email))
            # HIBP rate limit: max 1 req/1.5s
            time.sleep(1.6)
        except Exception:
            results.append(_manual_entry(email))

    return {
        "mode":          "api",
        "emails":        results,
        "total_breached": total_breached,
    }


def _build_manual_result(emails: List[str]) -> Dict:
    return {
        "mode":           "manual",
        "emails":         [_manual_entry(e) for e in emails],
        "total_breached": None,
    }


def _manual_entry(email: str) -> Dict:
    return {
        "email":        email,
        "breached":     None,
        "breach_count": None,
        "breach_names": [],
        "check_url":    _hibp_url(email),
    }


def _hibp_url(email: str) -> str:
    encoded = email.replace("@", "%40")
    return f"https://haveibeenpwned.com/account/{encoded}"
