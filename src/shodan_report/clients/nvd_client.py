import json
from typing import Any, Dict, Tuple, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class NvdClient:
	"""Minimal NVD v2 HTTP client used by reports.

	Fetches CVE data from the NVD v2 API and normalizes the response to a
	legacy-like shape with `CVE_Items` while preserving the raw v2 payload
	for CPE extraction.
	"""

	BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

	def __init__(self, api_key: Optional[str] = None, timeout: int = 20) -> None:
		self.api_key = api_key
		self.timeout = timeout

	def _default_headers(self) -> Dict[str, str]:
		headers: Dict[str, str] = {"User-Agent": "shodan-report-nvd/1.0"}
		if self.api_key:
			headers["apiKey"] = self.api_key
			headers["X-Api-Key"] = self.api_key
		return headers

	def fetch_cve(self, cve_id: str) -> Tuple[int, Dict[str, Any], str]:
		"""Fetch raw NVD v2 JSON as (status_code, headers, body)."""
		url = f"{self.BASE}?cveId={cve_id}"
		req = Request(url, headers=self._default_headers())
		try:
			with urlopen(req, timeout=self.timeout) as resp:
				status = getattr(resp, "status", 200)
				headers = dict(resp.headers.items()) if resp.headers else {}
				body = resp.read().decode("utf-8")
				return status, headers, body
		except HTTPError as exc:
			try:
				body = exc.read().decode("utf-8")
			except Exception:
				body = ""
			return exc.code, {}, body
		except URLError:
			return 0, {}, ""

	def fetch_cve_json(self, cve_id: str) -> Dict[str, Any]:
		status, headers, body = self.fetch_cve(cve_id)
		try:
			data = json.loads(body) if body else {}
		except Exception as exc:  # pragma: no cover - defensive
			raise ValueError(f"failed to parse CVE JSON: {exc}")

		# Normalize into legacy shape for _extract_nvd_fields
		try:
			vulns = data.get("vulnerabilities") or []
			v0 = vulns[0] if isinstance(vulns, list) and vulns else {}
			summary = None
			try:
				descs = v0.get("cve", {}).get("descriptions", [])
				if descs and isinstance(descs, list):
					summary = descs[0].get("value")
			except Exception:
				summary = None

			# CVSS extraction
			score = None
			metrics = v0.get("metrics") or v0.get("cve", {}).get("metrics") or {}
			for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3", "cvssMetricV2"):
				val = metrics.get(key)
				if isinstance(val, list) and val:
					m0 = val[0]
					if isinstance(m0, dict):
						if isinstance(m0.get("cvssData"), dict) and m0.get("cvssData", {}).get("baseScore") is not None:
							score = float(m0.get("cvssData", {}).get("baseScore"))
							break
						if isinstance(m0.get("cvssV3"), dict) and m0.get("cvssV3", {}).get("baseScore") is not None:
							score = float(m0.get("cvssV3", {}).get("baseScore"))
							break
						if isinstance(m0.get("cvssV2"), dict) and m0.get("cvssV2", {}).get("baseScore") is not None:
							score = float(m0.get("cvssV2", {}).get("baseScore"))
							break

			# Try to pick vendor/product from first CPE criteria
			vendor = ""
			product = ""
			configs = v0.get("cve", {}).get("configurations") or v0.get("configurations") or []
			criteria = None
			for node in configs if isinstance(configs, list) else []:
				nodes = node.get("nodes") or []
				for n in nodes:
					for m in n.get("cpeMatch") or []:
						if "criteria" in m:
							criteria = m.get("criteria")
							break
					if criteria:
						break
				if criteria:
					break
			if isinstance(criteria, str):
				parts = criteria.split(":")
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
				"impact": {"baseMetricV3": {"cvssV3": {"baseScore": score}}},
			}
			return {"CVE_Items": [item], "vulnerabilities": data.get("vulnerabilities")}
		except Exception:
			return data or {}


__all__ = ["NvdClient"]
