import json
import os
import time
from typing import Any, Dict, Optional
from urllib.request import Request, urlopen

import pytest

from shodan_report.pdf.sections.data.cve_enricher import _extract_nvd_fields


def _should_run_live() -> bool:
    return os.environ.get("NVD_LIVE_TESTS") == "1"


def _fetch_nvd_v2(cve_id: str) -> Dict[str, Any]:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"User-Agent": "shodan-report-nvd-tests/1.0"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
        headers["X-Api-Key"] = api_key
    req = Request(url, headers=headers)
    with urlopen(req, timeout=20) as resp:
        return json.load(resp)


def _find_first_cpe(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        for k in ("cpe23Uri", "cpe23", "cpe", "cpe22Uri", "criteria"):
            val = obj.get(k)
            if isinstance(val, str) and val.startswith("cpe:"):
                return val
        for v in obj.values():
            found = _find_first_cpe(v)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _find_first_cpe(v)
            if found:
                return found
    return None


def _extract_cvss_from_v2(vuln: Dict[str, Any]) -> Optional[float]:
    metrics = vuln.get("metrics") or vuln.get("cve", {}).get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3", "cvssMetricV2"):
        val = metrics.get(key)
        if isinstance(val, list) and val:
            m0 = val[0]
            if isinstance(m0, dict):
                if isinstance(m0.get("cvssData"), dict) and m0.get("cvssData", {}).get("baseScore") is not None:
                    return float(m0.get("cvssData", {}).get("baseScore"))
                if isinstance(m0.get("cvssV3"), dict) and m0.get("cvssV3", {}).get("baseScore") is not None:
                    return float(m0.get("cvssV3", {}).get("baseScore"))
                if isinstance(m0.get("cvssV2"), dict) and m0.get("cvssV2", {}).get("baseScore") is not None:
                    return float(m0.get("cvssV2", {}).get("baseScore"))
    return None


def _v2_to_legacy(v2_json: Dict[str, Any], cve_id: str) -> Dict[str, Any]:
    vulns = v2_json.get("vulnerabilities") or []
    vuln = vulns[0] if isinstance(vulns, list) and vulns else {}

    summary = None
    try:
        descs = vuln.get("cve", {}).get("descriptions", [])
        if descs and isinstance(descs, list):
            summary = descs[0].get("value")
    except Exception:
        summary = None

    cvss = _extract_cvss_from_v2(vuln)

    cpe = _find_first_cpe(vuln.get("cve", {}).get("configurations") or vuln.get("configurations") or vuln)
    vendor = ""
    product = ""
    if cpe:
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor = parts[3]
            product = parts[4]

    item = {
        "cve": {
            "CVE_data_meta": {"ID": cve_id},
            "description": {"description_data": [{"value": summary}]},
            "affects": {
                "vendor": {
                    "vendor_data": [
                        {
                            "vendor_name": vendor or "",
                            "product": {"product_data": [{"product_name": product or ""}]},
                        }
                    ]
                }
            },
        },
        "impact": {"baseMetricV3": {"cvssV3": {"baseScore": cvss}}},
    }
    return {"CVE_Items": [item]}


@pytest.mark.skipif(not _should_run_live(), reason="Set NVD_LIVE_TESTS=1 to run live NVD tests.")
def test_live_nvd_extracts_cvss() -> None:
    cve_id = "CVE-2021-44228"
    t0 = time.perf_counter()
    v2 = _fetch_nvd_v2(cve_id)
    legacy = _v2_to_legacy(v2, cve_id)
    fields = _extract_nvd_fields(legacy)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    print(f"[timing] {cve_id} total={elapsed_ms:.1f}ms")
    assert fields.get("cvss") is not None


@pytest.mark.skipif(not _should_run_live(), reason="Set NVD_LIVE_TESTS=1 to run live NVD tests.")
def test_live_nvd_extracts_service_mysql() -> None:
    cve_id = "CVE-2021-2307"
    t0 = time.perf_counter()
    v2 = _fetch_nvd_v2(cve_id)
    legacy = _v2_to_legacy(v2, cve_id)
    fields = _extract_nvd_fields(legacy)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    print(f"[timing] {cve_id} total={elapsed_ms:.1f}ms")
    service = (fields.get("service") or "").lower()
    assert service and "mysql" in service