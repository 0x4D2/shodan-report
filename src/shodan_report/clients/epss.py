"""
EPSS (Exploit Prediction Scoring System) Client.

Quelle: api.first.org/data/v1/epss — kostenlos, kein API-Key.
Gibt Wahrscheinlichkeit (0–1) zurück, dass eine CVE in den nächsten
30 Tagen aktiv ausgenutzt wird.
Non-fatal: leeres dict bei Fehler.
"""

from typing import Dict, List

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

_API_URL = "https://api.first.org/data/v1/epss"
_TIMEOUT = 10
_CHUNK   = 100  # max CVEs pro Request


def get_epss_scores(cve_ids: List[str]) -> Dict[str, float]:
    """
    Gibt dict zurück: CVE-ID (uppercase) → EPSS-Score (0.0–1.0).
    CVEs ohne EPSS-Eintrag fehlen im dict.
    Non-fatal: leeres dict bei Netzwerkfehler.
    """
    if not cve_ids or not _HAS_REQUESTS:
        return {}

    result: Dict[str, float] = {}
    try:
        for i in range(0, len(cve_ids), _CHUNK):
            chunk = cve_ids[i:i + _CHUNK]
            resp = _requests.get(
                _API_URL,
                params={"cve": ",".join(chunk)},
                timeout=_TIMEOUT,
            )
            if resp.status_code != 200:
                continue
            for entry in (resp.json().get("data") or []):
                cid   = str(entry.get("cve") or "").upper()
                score = entry.get("epss")
                if cid and score is not None:
                    try:
                        result[cid] = float(score)
                    except (ValueError, TypeError):
                        pass
    except Exception:
        pass

    return result
