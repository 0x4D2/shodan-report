"""
GreyNoise Community API Client.

GET /v3/community/{ip}  — kostenloses Tier, kein Account nötig (API-Key optional).
Non-fatal: alle Fehler → available=False, graceful fallback.
"""

import os
from typing import Optional

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


_API_BASE = "https://api.greynoise.io"
_TIMEOUT  = 5  # Sekunden


def get_greynoise_status(ip: str, api_key: Optional[str] = None) -> dict:
    """
    Fragt GreyNoise Community API für eine IP ab.

    Rückgabe:
    {
        "available":      True | False,
        "noise":          True | False,
        "riot":           True | False,
        "classification": "malicious" | "benign" | "unknown",
        "name":           "Host Europe GmbH" | "",
        "last_seen":      "2026-04-15" | "",
        "link":           "https://viz.greynoise.io/ip/1.2.3.4",
    }

    Bei Fehler (kein Netz, kein API-Key, 404, Timeout …) wird
    {"available": False, ...alle anderen Felder leer/False} zurückgegeben.
    """
    _empty = {
        "available":      False,
        "noise":          False,
        "riot":           False,
        "classification": "unknown",
        "name":           "",
        "last_seen":      "",
        "link":           f"https://viz.greynoise.io/ip/{ip}",
    }

    if not ip or not _HAS_REQUESTS:
        return _empty

    key = api_key or os.getenv("GREYNOISE_API_KEY", "")
    headers = {"Accept": "application/json"}
    if key:
        headers["key"] = key

    try:
        resp = _requests.get(
            f"{_API_BASE}/v3/community/{ip}",
            headers=headers,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            # IP not in GreyNoise index → clean / unbekannt
            return {**_empty, "available": True, "noise": False}
        if resp.status_code != 200:
            return _empty

        data = resp.json()
        return {
            "available":      True,
            "noise":          bool(data.get("noise", False)),
            "riot":           bool(data.get("riot", False)),
            "classification": str(data.get("classification") or "unknown").lower(),
            "name":           str(data.get("name") or ""),
            "last_seen":      str(data.get("last_seen") or ""),
            "link":           f"https://viz.greynoise.io/ip/{ip}",
        }
    except Exception:
        return _empty
